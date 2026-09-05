package tlsquery

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func resolveProxy(endpoint string, opts QueryOptions) (*url.URL, error) {
	proxyStr := opts.Proxy

	if proxyStr != "" {
		if !strings.Contains(proxyStr, "://") {
			proxyStr = "http://" + proxyStr
		}
		return parseProxy(proxyStr)
	}

	req := &http.Request{URL: &url.URL{Scheme: "https", Host: endpoint}}
	proxy, err := http.ProxyFromEnvironment(req)
	if err != nil || proxy == nil {
		return proxy, err
	}
	return parseProxy(proxy.String())
}

func dialViaProxy(endpoint string, proxyURL *url.URL, connectTimeout, handshakeTimeout time.Duration) (net.Conn, error) {
	return dialViaProxyContext(context.Background(), endpoint, proxyURL, connectTimeout, handshakeTimeout)
}
func dialViaProxyContext(ctx context.Context, endpoint string, proxyURL *url.URL, connectTimeout, handshakeTimeout time.Duration) (net.Conn, error) {
	proxyAddr := proxyURL.Host
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		port := "80"
		if proxyURL.Scheme == "https" {
			port = "443"
		}
		proxyAddr = net.JoinHostPort(proxyURL.Hostname(), port)
	}

	dialer := &net.Dialer{Timeout: connectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", proxyAddr, err)
	}
	rawConn := conn
	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	if err := conn.SetDeadline(phaseDeadline(ctx, handshakeTimeout)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to configure proxy timeout: %w", err)
	}

	if proxyURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: proxyURL.Hostname()})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake with proxy failed: %w", err)
		}
		conn = tlsConn
	}

	br := bufio.NewReader(conn)

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: endpoint},
		Host:   endpoint,
		Header: make(http.Header),
	}

	if proxyURL.User != nil {
		user := proxyURL.User.Username()
		pass, _ := proxyURL.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read proxy response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to clear proxy timeout: %w", err)
	}

	return &bufferedConn{Conn: conn, r: br}, nil
}

func ValidateProxy(value string) error {
	if value == "" {
		return nil
	}
	_, err := parseProxy(value)
	return err
}
func parseProxy(value string) (*url.URL, error) {
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	proxy, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	if proxy.Scheme != "http" && proxy.Scheme != "https" {
		return nil, fmt.Errorf("unsupported proxy scheme %q: use http or https", proxy.Scheme)
	}
	if proxy.Hostname() == "" || strings.ContainsAny(proxy.Hostname(), " \t\r\n") || proxy.Path != "" && proxy.Path != "/" || proxy.RawQuery != "" || proxy.Fragment != "" {
		return nil, fmt.Errorf("proxy URL must contain a host and optional port, without a path, query, or fragment")
	}
	if port := proxy.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("proxy port must be between 1 and 65535")
		}
	}
	return proxy, nil
}
