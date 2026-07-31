package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

func helloID(profile string) (utls.ClientHelloID, error) {
	switch strings.ToLower(profile) {
	case "chrome", "chrome120", "edge", "edge120":
		return utls.HelloChrome_Auto, nil
	case "firefox", "firefox120":
		return utls.HelloFirefox_Auto, nil
	case "ios", "ios15", "safari", "safari17":
		return utls.HelloIOS_Auto, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unsupported profile: %s", profile)
	}
}

func fetchWithUTLS(rawURL string, profile string, timeout time.Duration) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("only https URLs are supported")
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	path := parsed.RequestURI()
	if path == "" {
		path = "/"
	}

	hello, err := helloID(profile)
	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{Timeout: timeout}
	tcpConn, err := dialer.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	defer tcpConn.Close()
	_ = tcpConn.SetDeadline(time.Now().Add(timeout))

	config := &utls.Config{ServerName: host, InsecureSkipVerify: false}
	conn := utls.UClient(tcpConn, config, hello)
	if err := conn.Handshake(); err != nil {
		return nil, err
	}
	defer conn.Close()

	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36\r\nAccept: application/json,text/plain,*/*\r\nConnection: close\r\n\r\n", path, parsed.Host)
	if _, err := conn.Write([]byte(request)); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	response, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	parts := strings.SplitN(string(response), "\r\n\r\n", 2)
	if len(parts) == 2 {
		return []byte(parts[1]), nil
	}
	return response, nil
}

func main() {
	profile := flag.String("profile", "chrome120", "JA3 profile name: chrome120, firefox120, safari17, edge120, ios15")
	target := flag.String("url", "https://ja3er.com/json", "verification HTTPS URL")
	timeoutSeconds := flag.Int("timeout", 20, "timeout in seconds")
	flag.Parse()

	body, err := fetchWithUTLS(*target, *profile, time.Duration(*timeoutSeconds)*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ja3probe error: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(string(body))
}
