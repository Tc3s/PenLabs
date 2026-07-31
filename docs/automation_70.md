# PenLabs Automation 70% Operating Guide

Ngay 2026-07-17, PenLabs da co lop automation du manh cho recon, initial DAST, triage va report handoff. Tai lieu nay mo ta dung nang luc hien tai de van hanh thuc chien, khong coi tool la auto-pentest hoan chinh.

## Muc Tieu Thuc Te

PenLabs dat gan moc 70% automation khi:
- Scope/RoE ro rang va da cau hinh dung.
- External tools duoc cai day du: httpx, katana, nuclei, dalfox, sqlmap, arjun, kiterunner, nmap, wpscan, ffuf, gowitness tuy mode.
- Auth/cookie/token hop le neu scan sau login.
- Chon dung tactical mode va option theo muc tieu.
- Operator van lam 30% manual: xac minh impact, workflow logic, business logic, exploit chain va report client-ready.

## 7 Lop Automation Da Dong Bo

| Phase | Thanh phan | File chinh | Ket qua |
|---|---|---|---|
| 1 | Endpoint feedback loop | `core/endpoint_store.py`, `core/scanner_router.py` | Katana/LinkFinder/Kiterunner/Arjun/web URLs gom vao `endpoint_store` |
| 2 | Auth context | `core/auth_context.py` | User A/B, cookie, CSRF, token refresh profile |
| 3 | Verification pass 2 | `core/verification.py`, `core/verification_replay.py` | Bucket + replay HTTP co gioi han cho finding de false-positive |
| 4 | Strategy profiles | `core/plugin_strategy.py`, plugins | Nuclei/SQLMap/Dalfox/WPScan/Nmap nhan profile thuc thi |
| 5 | Correlation/chaining | `core/correlation.py` | Attack paths co score va manual next step |
| 6 | Cloud/infra depth | `core/cloud_infra_depth.py` | High-value services va cloud triage items |
| 7 | Report/regression | `core/reporter.py`, `core/dry_run_snapshot.py`, `tests/test_automation_contracts.py` | Confirmed/Suspected/Manual Review/Noise + snapshot |

## Knowledge-Base Integration

PenLabs co adapter `core/knowledge_base.py` de dung bo tri thuc WSTG/PortSwigger/framework/payload cards nhu mot lop dieu phoi, khong phai exploit engine.

Mac dinh adapter tim knowledge-base theo thu tu hardcoded:

```bash
./knowledge-base
./data/knowledge-base
/home/tcus/Desktop/WEb/wstg-pentest/knowledge-base
```

Co the override bang env neu clone repo tren may khac:

```bash
export PENLABS_KNOWLEDGE_BASE=/path/to/knowledge-base
```

Du lieu sinh ra trong output:
- `dast_findings[].technique_codes`
- `dast_findings[].wstg_refs`
- `dast_findings[].guide_path`
- `dast_findings[].manual_next`
- `knowledge_profile`
- `wstg_coverage`
- `manual_handoff`

Pham vi ap dung:
- `CROSSWALK`/WSTG: coverage refs va manual gaps.
- `frameworks/*`: stack-aware first tests va Nuclei tag hints.
- `advanced/impact-chains.md`: dung lam huong correlation/manual chain, khong tu dong leo thang impact.
- `payloads/*`: chi tham chieu guide/manual next step; khong nap nguyen payload pack vao scan runtime.

Ly do gioi han: Markdown KB co gia tri thuc chien nhung chua phai structured runtime data. Muon day automation sau hon thi can curate canary payload rieng va test RoE rieng cho tung client.

## Tactical Modes

| Mode | Khi dung | Automation ky vong |
|---|---|---:|
| `asset-discovery` | Subdomain, live URL, JS, endpoint, secret, exposure | 70-80% |
| `web-vuln` | Web DAST ban dau, XSS/CORS/BXSS/Mass Assignment | 60-75% |
| `api-bounty` | API/web logic flaw pipeline day du hon | 60-75% |
| `api-breach` | Origin/API exposure, Arjun, Nuclei API/misconfig | 55-70% |
| `cloud-native` | S3/GCP/Azure/K8s/takeover/cloud templates | 50-70% |
| `infra-smash` | Port verify, Nmap NSE, infra triage | 55-70% |
| `sniper` | Mot target chinh, scan gon | 55-70% |
| `stealth` | Low-noise OSINT/external quiet scan | 45-65% |
| `full-audit` | Coverage sau, noise cao | 60-75% neu du tool |

## Auth Profile

PenLabs co the doc auth profile qua bien moi truong:

```bash
export PENLABS_AUTH_PROFILE=examples/auth_profile.example.json
```

Hoac van dung `--auth-config` de khoi tao `utils/auth_manager.py`. `AuthContext` se uu tien profile trong `PENLABS_AUTH_PROFILE` khi router duoc tao.

Profile ho tro:
- `headers`: header nen cho moi request.
- `cookie`: cookie mac dinh.
- `identities.userA/userB`: token/header/cookie rieng cho BOLA/Mass Assignment.
- `refresh`: login/refresh endpoint, JSON payload, `token_path`, `cookie_path`, `csrf_path`.

Khuyen nghi:
- Dung User A/B token khac nhau khi bat BOLA/Mass Assignment.
- Dat refresh interval vua phai de tranh spam login endpoint.
- Khong commit token that vao repo.

## Verification Pass 2

Mac dinh replay pass 2 dang tat de tranh phat sinh traffic ngoai du kien.

Bat co kiem soat:

```bash
export VERIFICATION_PASS2_ENABLED=true
export VERIFICATION_PASS2_MAX_FINDINGS=20
export VERIFICATION_PASS2_TIMEOUT=8
```

Replay hien tap trung vao cac finding de false-positive:
- `bypass_403`
- `cache_poisoning`
- `open_redirect`
- `cors`
- `crlf`
- `ssrf` co OOB/evidence
- `mass_assignment`, `bola`, `race_condition`, `blind_xss` neu confidence cao

Ket qua vao:
- `dast_findings[].verification_status`
- `verification_buckets`
- `verification_summary`
- report Markdown

## Wordlist Automation

`core/wordlist_registry.py` tu dong chon wordlist theo purpose/mode:
- `ffuf` web discovery: `web_content`.
- `stealth`/`sniper`: uu tien `sensitive_paths_2026.txt` de giam noise.
- `full-audit`/`infra-smash`: uu tien `raft-large-directories.txt` de tang coverage.
- Kiterunner: `routes-small.kite`.
- S3Scanner: `s3_buckets.txt`.
- Password lists chi duoc khai bao trong registry, khong auto brute-force.

Override bang env:
```bash
export PENLABS_WEB_WORDLIST=/path/to/common.txt
export PENLABS_WEB_DEEP_WORDLIST=/path/to/raft-large-directories.txt
export KITERUNNER_WORDLIST=/path/to/routes.kite
export PENLABS_PARAM_WORDLIST=/path/to/params.txt
export PENLABS_S3_WORDLIST=/path/to/s3_buckets.txt
```

Moi scan se co `wordlist_profile` trong output/report de audit source/path da dung.

## Report Buckets

Report chia finding thanh:
- `confirmed`: co evidence/replay/OOB/manh.
- `suspected`: co tin hieu can manual confirm.
- `manual_review`: can nguoi test workflow/impact.
- `noise`: status/error pattern nhieu kha nang false-positive.

Attack path co `score` de uu tien manual:
- Open Redirect + OAuth/SSO
- CORS + XSS
- SSRF + Cloud Metadata
- CRLF + Cache Poisoning
- Blind XSS + Privileged Workflow

## Van Hanh Khuyen Nghi

Quy trinh phu hop nhat:

1. Chay `asset-discovery` de lay endpoint store va raw artifacts.
2. Chay `web-vuln` neu muc tieu la web app thong thuong.
3. Chay `api-bounty` voi auth profile neu co API/login.
4. Bat `VERIFICATION_PASS2_ENABLED=true` khi RoE cho phep replay xac minh.
5. Doc `attack_surface_report.md`, `potential_logic_bugs.txt`, `web_vuln_handoff.md`.
6. Lam manual 30% tren bucket `suspected` va `manual_review`.

## Gioi Han Con Lai

Tool chua thay the nguoi test:
- Business logic multi-step.
- Payment/account/workflow abuse.
- Auth flow phuc tap tuy tung client.
- Cloud permission impact that su.
- Exploit chain can xac nhan an toan theo RoE.

Do do moc 70% nen hieu la 70% automation cho collection, discovery, triage va handoff, khong phai 70% finding da san sang nop report.
