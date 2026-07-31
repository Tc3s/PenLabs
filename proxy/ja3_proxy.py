#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
P1-1 JA3 SOCKS5 Proxy with TLS MITM Interception.

This module provides a local SOCKS5 CONNECT proxy that intercepts TLS
connections and re-establishes them using curl_cffi with browser-like
JA3 fingerprints.  This ensures ALL traffic from external tools (nuclei,
curl, httpx, katana) routed through this proxy will appear to originate
from a real browser TLS stack at the target server.

Architecture:
  Client (nuclei/curl) ──TLS──> JA3Proxy ──curl_cffi(chrome120)──> Target
                                  │
                          TLS terminated here
                          (self-signed CA cert)

For non-TLS connections (plain HTTP), the proxy falls back to a simple
TCP bidirectional relay as before.

If curl_cffi is not installed, the proxy falls back to plain TCP relay
mode and logs a warning.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import socket
import ssl
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

# ── Optional curl_cffi for JA3 impersonation ─────────────────────────
try:
    from curl_cffi import requests as curl_requests
    HAS_CURL_CFFI = True
except ImportError:
    curl_requests = None
    HAS_CURL_CFFI = False

# ── Optional utls (kept for backward compatibility with ja3probe) ────
try:  # pragma: no cover
    import utls  # type: ignore
    HAS_UTLS = True
except Exception:  # pragma: no cover
    utls = None
    HAS_UTLS = False

log = logging.getLogger("JA3Proxy")

SOCKS5_VERSION = 0x05
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04

# Ports that indicate TLS traffic requiring MITM interception
_TLS_PORTS = {443, 8443, 4443, 9443}


def _default_ca_dir() -> Path:
    """Keep generated MITM CA material out of the repo tree."""
    return Path(os.getenv("PENLABS_JA3_CA_DIR", Path.home() / ".cache" / "penlabs" / "ja3_ca"))


# ══════════════════════════════════════════════════════════════════════
# Self-Signed CA Certificate Generation (on-the-fly)
# ══════════════════════════════════════════════════════════════════════

def _generate_self_signed_ca(ca_dir: Path) -> Tuple[Path, Path]:
    """
    Generate a self-signed CA certificate and private key for TLS MITM.
    Stored in ca_dir/ca.pem and ca_dir/ca.key. Reused across sessions.
    """
    ca_cert_path = ca_dir / "ca.pem"
    ca_key_path = ca_dir / "ca.key"

    if ca_cert_path.exists() and ca_key_path.exists():
        return ca_cert_path, ca_key_path

    ca_dir.mkdir(parents=True, exist_ok=True)

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        # Generate CA key
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Build CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PenLabs JA3 Proxy CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "PenLabs MITM CA"),
        ])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

        # Write to disk
        ca_key_path.write_bytes(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        log.info("[JA3-CA] Generated self-signed CA: %s", ca_cert_path)
        return ca_cert_path, ca_key_path

    except ImportError:
        log.warning("[JA3-CA] 'cryptography' package not installed; TLS MITM disabled")
        raise


def _generate_host_cert(ca_cert_path: Path, ca_key_path: Path, hostname: str) -> Tuple[Path, Path]:
    """
    Generate a per-host TLS certificate signed by the proxy CA.
    Certificates are cached in the same directory as the CA cert.
    """
    safe_name = hostname.replace("*", "_star_").replace(":", "_")
    host_cert_path = ca_cert_path.parent / f"host_{safe_name}.pem"
    host_key_path = ca_cert_path.parent / f"host_{safe_name}.key"

    if host_cert_path.exists() and host_key_path.exists():
        return host_cert_path, host_key_path

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime

    # Load CA
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)

    # Generate host key
    host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    # SAN with the hostname (supports both DNS names and IP addresses)
    san_entries: list = []
    try:
        import ipaddress
        san_entries.append(x509.IPAddress(ipaddress.ip_address(hostname)))
    except ValueError:
        san_entries.append(x509.DNSName(hostname))

    host_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(host_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    host_key_path.write_bytes(
        host_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    host_cert_path.write_bytes(host_cert.public_bytes(serialization.Encoding.PEM))
    log.debug("[JA3-CA] Generated host cert for %s", hostname)
    return host_cert_path, host_key_path


# ══════════════════════════════════════════════════════════════════════
# JA3 Profile Store (unchanged)
# ══════════════════════════════════════════════════════════════════════

class JA3ProfileStore:
    """Load browser JA3 profile metadata from YAML."""

    def __init__(self, profiles_path: Optional[os.PathLike | str] = None):
        self.path = Path(profiles_path) if profiles_path else Path(__file__).with_name("ja3_profiles.yaml")
        self.profiles = self._load_profiles(self.path)

    @staticmethod
    def _load_profiles(path: Path) -> Dict[str, Dict[str, Any]]:
        if not path.exists():
            log.warning("[JA3] profile file missing: %s", path)
            return {}
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
            profiles = data.get("profiles", {})
            return profiles if isinstance(profiles, dict) else {}
        except Exception as exc:
            log.warning("[JA3] failed to load profiles from %s: %s", path, exc)
            return {}

    def get(self, profile: str) -> Dict[str, Any]:
        return self.profiles.get(profile, {})


# ══════════════════════════════════════════════════════════════════════
# JA3 SOCKS5 Proxy with TLS MITM
# ══════════════════════════════════════════════════════════════════════

@dataclass
class JA3Proxy:
    profile: Dict[str, Any]
    profile_name: str = "chrome120"
    listen_host: str = "127.0.0.1"
    listen_port: int = 1080
    profiles_path: Optional[str] = None
    # TLS MITM state
    _mitm_enabled: bool = field(default=False, init=False, repr=False)
    _ca_cert_path: Optional[Path] = field(default=None, init=False, repr=False)
    _ca_key_path: Optional[Path] = field(default=None, init=False, repr=False)

    def __init__(
        self,
        profile: str = "chrome120",
        profiles_path: Optional[os.PathLike | str] = None,
        listen_host: str = "127.0.0.1",
        listen_port: int = 1080,
        ca_dir: Optional[str] = None,
    ):
        self.profile_name = profile
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.profiles_path = str(profiles_path) if profiles_path else None
        self.store = JA3ProfileStore(profiles_path)
        self.profile = self.store.get(profile)
        self._spec = None
        self._mitm_enabled = False
        self._ca_cert_path = None
        self._ca_key_path = None

        # Initialize TLS MITM infrastructure
        self._init_mitm(ca_dir)

    def _init_mitm(self, ca_dir: Optional[str] = None) -> None:
        """Initialize TLS MITM CA certificate for connection interception."""
        if not HAS_CURL_CFFI:
            log.warning(
                "[JA3-MITM] curl_cffi not installed; TLS MITM disabled. "
                "JA3 spoofing will NOT work for external tools. "
                "Install curl_cffi to enable: pip install curl_cffi"
            )
            return

        try:
            ca_path = Path(ca_dir) if ca_dir else _default_ca_dir()
            self._ca_cert_path, self._ca_key_path = _generate_self_signed_ca(ca_path)
            self._mitm_enabled = True
            log.info("[JA3-MITM] TLS interception enabled (CA=%s)", self._ca_cert_path)
        except Exception as e:
            log.warning("[JA3-MITM] Failed to initialize CA: %s. Falling back to plain relay.", e)
            self._mitm_enabled = False

    def status(self) -> Dict[str, Any]:
        return {
            "listen": f"{self.listen_host}:{self.listen_port}",
            "profile": self.profile_name,
            "ja3_hash": self.profile.get("ja3_hash", ""),
            "utls_available": HAS_UTLS,
            "curl_cffi_available": HAS_CURL_CFFI,
            "mitm_enabled": self._mitm_enabled,
            "ca_dir": str(self._ca_cert_path.parent) if self._ca_cert_path else "",
        }

    def get_spec(self) -> Any:
        """Return a utls ClientHello spec if utls exists; otherwise fail closed."""
        if not HAS_UTLS:
            raise RuntimeError("utls not installed; install a Python utls/tls-client backend or use env/flag routing only")
        if self._spec is None:
            self._spec = {"profile": self.profile_name, **self.profile}
        return self._spec

    async def start(self) -> None:
        server = await asyncio.start_server(self._handle_client, self.listen_host, self.listen_port)
        log.info(
            "[JA3] SOCKS5 proxy started on %s:%s (profile=%s hash=%s mitm=%s curl_cffi=%s)",
            self.listen_host,
            self.listen_port,
            self.profile_name,
            self.profile.get("ja3_hash", "unknown"),
            self._mitm_enabled,
            HAS_CURL_CFFI,
        )
        async with server:
            await server.serve_forever()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._socks5_handshake(reader, writer)
            host, port = await self._read_connect_request(reader, writer)

            if self._mitm_enabled and port in _TLS_PORTS:
                # TLS MITM path: intercept, decrypt, re-send with JA3 spoof
                await self._handle_tls_mitm(reader, writer, host, port)
            else:
                # Plain TCP relay for non-TLS connections
                remote_reader, remote_writer = await asyncio.open_connection(host, port)
                await self._relay_bidirectional(reader, writer, remote_reader, remote_writer)
        except Exception as exc:
            log.debug("[JA3] client handler failed: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_tls_mitm(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        """
        TLS MITM interception handler.

        1. Generate a per-host certificate signed by proxy CA
        2. Perform TLS handshake with the client using the fake cert
        3. Read the cleartext HTTP request from the client
        4. Forward it to the target using curl_cffi with JA3 impersonation
        5. Send the response back to the client over the TLS tunnel

        This is the key mechanism that makes JA3 spoofing work for external
        tools: the tool connects to our proxy via TLS (seeing our fake cert),
        but the actual outbound connection to the target uses curl_cffi's
        Chrome 120 TLS fingerprint.
        """
        # Step 1: Generate host certificate
        try:
            host_cert, host_key = _generate_host_cert(
                self._ca_cert_path, self._ca_key_path, host
            )
        except Exception as e:
            log.warning("[JA3-MITM] Cert generation failed for %s: %s. Falling back to relay.", host, e)
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
            await self._relay_bidirectional(client_reader, client_writer, remote_reader, remote_writer)
            return

        # Step 2: TLS handshake with client (server-side SSL context)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(str(host_cert), str(host_key))
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        transport = client_writer.transport
        loop = asyncio.get_event_loop()

        try:
            tls_transport = await loop.start_tls(
                transport, ssl_ctx, server_side=True,
            )
            # Replace the reader/writer with TLS-wrapped versions
            tls_reader = asyncio.StreamReader()
            tls_protocol = asyncio.StreamReaderProtocol(tls_reader)
            tls_transport.set_protocol(tls_protocol)
            tls_writer = asyncio.StreamWriter(tls_transport, tls_protocol, tls_reader, loop)
        except Exception as e:
            log.debug("[JA3-MITM] TLS handshake with client failed for %s: %s", host, e)
            return

        # Step 3 & 4: Read client HTTP request and forward via curl_cffi
        try:
            await self._mitm_http_loop(tls_reader, tls_writer, host, port)
        except Exception as e:
            log.debug("[JA3-MITM] HTTP relay error for %s: %s", host, e)
        finally:
            try:
                tls_writer.close()
                await tls_writer.wait_closed()
            except Exception:
                pass

    async def _mitm_http_loop(
        self,
        tls_reader: asyncio.StreamReader,
        tls_writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        """
        Read HTTP requests from the decrypted TLS stream and forward them
        through curl_cffi with JA3 impersonation to the real target.
        Supports HTTP/1.1 keep-alive (multiple requests per connection).
        """
        target_base = f"https://{host}" if port == 443 else f"https://{host}:{port}"

        while True:
            # Read the HTTP request line
            try:
                request_line = await asyncio.wait_for(
                    tls_reader.readline(), timeout=30.0
                )
            except (asyncio.TimeoutError, ConnectionError):
                break

            if not request_line:
                break

            request_line_str = request_line.decode("utf-8", errors="replace").strip()
            if not request_line_str:
                break

            # Parse method, path, version
            parts = request_line_str.split(" ", 2)
            if len(parts) < 2:
                break
            method = parts[0].upper()
            path = parts[1]

            # Read headers
            headers = {}
            content_length = 0
            while True:
                header_line = await tls_reader.readline()
                if not header_line or header_line.strip() == b"":
                    break
                try:
                    line_str = header_line.decode("utf-8", errors="replace").strip()
                    if ":" in line_str:
                        key, _, val = line_str.partition(":")
                        key = key.strip()
                        val = val.strip()
                        headers[key] = val
                        if key.lower() == "content-length":
                            content_length = int(val)
                except Exception:
                    continue

            # Read body if present
            body = None
            if content_length > 0:
                body = await tls_reader.readexactly(content_length)

            # Build target URL
            target_url = f"{target_base}{path}"

            # Forward via curl_cffi with JA3 impersonation
            try:
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self._curl_cffi_forward(method, target_url, headers, body),
                )
            except Exception as e:
                # Send 502 Bad Gateway on forward failure
                error_body = f"JA3 Proxy MITM forward error: {e}"
                error_resp = (
                    f"HTTP/1.1 502 Bad Gateway\r\n"
                    f"Content-Length: {len(error_body)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{error_body}"
                )
                tls_writer.write(error_resp.encode("utf-8"))
                await tls_writer.drain()
                break

            # Construct HTTP response
            status_line = f"HTTP/1.1 {response.status_code} OK\r\n"
            resp_headers = ""
            for k, v in response.headers.items():
                # Skip hop-by-hop headers
                if k.lower() in ("transfer-encoding", "connection", "keep-alive"):
                    continue
                resp_headers += f"{k}: {v}\r\n"

            resp_body = response.content or b""
            resp_headers += f"Content-Length: {len(resp_body)}\r\n"
            resp_headers += "Connection: keep-alive\r\n"

            full_response = (
                status_line + resp_headers + "\r\n"
            ).encode("utf-8") + resp_body

            tls_writer.write(full_response)
            await tls_writer.drain()

            # Check if client wants to close
            connection_header = headers.get("Connection", "").lower()
            if connection_header == "close":
                break

    def _curl_cffi_forward(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[bytes] = None,
    ) -> Any:
        """
        Forward an HTTP request using curl_cffi with Chrome 120 JA3 impersonation.
        This is the function that actually performs the JA3 fingerprint spoofing.
        """
        # Remove proxy-internal headers that would leak our presence
        forward_headers = {}
        skip_headers = {"host", "proxy-connection", "proxy-authorization"}
        for k, v in headers.items():
            if k.lower() not in skip_headers:
                forward_headers[k] = v

        kwargs = {
            "headers": forward_headers,
            "verify": os.getenv("PENLABS_JA3_INSECURE", "false").lower() != "true",
            "timeout": 30,
            "allow_redirects": False,
            "impersonate": self.profile_name or "chrome120",
        }

        if body:
            kwargs["data"] = body

        return curl_requests.request(method, url, **kwargs)

    # ── SOCKS5 Protocol Implementation ────────────────────────────────

    async def _socks5_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        version, nmethods = struct.unpack("!BB", await reader.readexactly(2))
        if version != SOCKS5_VERSION:
            raise ValueError("unsupported SOCKS version")
        await reader.readexactly(nmethods)
        writer.write(struct.pack("!BB", SOCKS5_VERSION, 0x00))
        await writer.drain()

    async def _read_connect_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Tuple[str, int]:
        version, cmd, _rsv, atyp = struct.unpack("!BBBB", await reader.readexactly(4))
        if version != SOCKS5_VERSION or cmd != SOCKS5_CMD_CONNECT:
            raise ValueError("only SOCKS5 CONNECT is supported")

        if atyp == SOCKS5_ATYP_DOMAIN:
            length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(length)).decode("idna")
        elif atyp == SOCKS5_ATYP_IPV4:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == SOCKS5_ATYP_IPV6:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            raise ValueError("unsupported SOCKS address type")

        port = struct.unpack("!H", await reader.readexactly(2))[0]
        writer.write(
            struct.pack("!BBBB", SOCKS5_VERSION, 0x00, 0x00, SOCKS5_ATYP_IPV4)
            + socket.inet_aton("0.0.0.0")
            + struct.pack("!H", 0)
        )
        await writer.drain()
        return host, port

    async def _relay_bidirectional(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
    ) -> None:
        """Plain TCP bidirectional relay for non-TLS connections."""
        async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            finally:
                try:
                    dst.close()
                    await dst.wait_closed()
                except Exception:
                    pass

        await asyncio.gather(pipe(client_reader, remote_writer), pipe(remote_reader, client_writer), return_exceptions=True)


def build_go_tool_proxy_args(tool: str, host: str = "127.0.0.1", port: int = 1080) -> List[str]:
    """Return native proxy flags for common Go tools."""
    socks_addr = f"{host}:{int(port)}"
    socks_url = f"socks5://{socks_addr}"
    tool = (tool or "").lower()
    if tool == "nuclei":
        return ["-proxy-socks5", socks_addr]
    if tool == "httpx":
        return ["-http-proxy", socks_url]
    if tool == "katana":
        return ["-proxy", socks_url]
    return []


def _parse_listen(value: str) -> Tuple[str, int]:
    host, _, port = value.rpartition(":")
    if not host or not port:
        raise argparse.ArgumentTypeError("listen must be host:port")
    return host, int(port)


def main() -> None:
    parser = argparse.ArgumentParser(description="PenLabs JA3 SOCKS5 proxy with TLS MITM")
    parser.add_argument("--listen", default="127.0.0.1:1080", help="listen address host:port")
    parser.add_argument("--profile", default="chrome120", help="JA3 profile name")
    parser.add_argument("--profiles", default=None, help="path to ja3_profiles.yaml")
    parser.add_argument("--ca-dir", default=None, help="directory for CA certificates (default: ~/.cache/penlabs/ja3_ca)")
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format="%(levelname)s: %(message)s")
    host, port = _parse_listen(args.listen)
    proxy = JA3Proxy(
        profile=args.profile,
        profiles_path=args.profiles,
        listen_host=host,
        listen_port=port,
        ca_dir=args.ca_dir,
    )
    if not HAS_CURL_CFFI:
        log.warning("[JA3] curl_cffi unavailable; running plain SOCKS5 relay without JA3 spoofing")
    elif not proxy._mitm_enabled:
        log.warning("[JA3] MITM disabled (missing 'cryptography' package); running plain SOCKS5 relay")
    asyncio.run(proxy.start())


if __name__ == "__main__":
    main()
