package tlsquery

import (
	"bufio"
	"fmt"
	"net"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// defaultStartTLSPort returns the standard plaintext port for a STARTTLS protocol.
func defaultStartTLSPort(protocol string) string {
	switch protocol {
	case "smtp":
		return "587"
	case "imap":
		return "143"
	case "pop3":
		return "110"
	case "ldap":
		return "389"
	default:
		return ""
	}
}

// ValidStartTLSProtocol returns true if the given protocol name is supported.
func ValidStartTLSProtocol(protocol string) bool {
	switch protocol {
	case "smtp", "imap", "pop3", "ldap":
		return true
	default:
		return false
	}
}

// negotiateStartTLS performs the protocol-specific STARTTLS handshake on an
// established plaintext connection. After a successful return the connection
// is ready for a TLS handshake.
func negotiateStartTLS(conn net.Conn, protocol string) error {
	switch protocol {
	case "smtp":
		return negotiateSMTP(conn)
	case "imap":
		return negotiateIMAP(conn)
	case "pop3":
		return negotiatePOP3(conn)
	case "ldap":
		return negotiateLDAP(conn)
	default:
		return fmt.Errorf("unsupported STARTTLS protocol: %s", protocol)
	}
}

func negotiateSMTP(conn net.Conn) error {
	r := bufio.NewReader(conn)

	// Read greeting.
	if err := expectSMTPReply(r, "220"); err != nil {
		return fmt.Errorf("SMTP greeting: %w", err)
	}

	// Send EHLO.
	if _, err := fmt.Fprintf(conn, "EHLO tlsctl\r\n"); err != nil {
		return fmt.Errorf("SMTP EHLO: %w", err)
	}
	if err := expectSMTPReply(r, "250"); err != nil {
		return fmt.Errorf("SMTP EHLO response: %w", err)
	}

	// Send STARTTLS.
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("SMTP STARTTLS: %w", err)
	}
	if err := expectSMTPReply(r, "220"); err != nil {
		return fmt.Errorf("SMTP STARTTLS response: %w", err)
	}

	return nil
}

// expectSMTPReply reads SMTP multi-line replies and checks the response code.
func expectSMTPReply(r *bufio.Reader, expectedCode string) error {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return fmt.Errorf("unexpected response: %q", line)
		}
		code := line[:3]
		if code != expectedCode {
			return fmt.Errorf("unexpected response: %q", line)
		}
		// A space after the code means this is the last line.
		if len(line) == 3 || line[3] == ' ' {
			return nil
		}
	}
}

func negotiateIMAP(conn net.Conn) error {
	r := bufio.NewReader(conn)

	// Read server greeting (starts with "* ").
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("IMAP greeting: %w", err)
	}
	if !strings.HasPrefix(line, "* ") {
		return fmt.Errorf("IMAP: unexpected greeting: %q", strings.TrimRight(line, "\r\n"))
	}

	// Send STARTTLS command.
	if _, err := fmt.Fprintf(conn, "a001 STARTTLS\r\n"); err != nil {
		return fmt.Errorf("IMAP STARTTLS: %w", err)
	}

	// Read lines until we see the tagged response (skip untagged "* " lines).
	for {
		line, err = r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("IMAP STARTTLS response: %w", err)
		}
		if strings.HasPrefix(line, "* ") {
			continue
		}
		if strings.HasPrefix(line, "a001 OK") {
			return nil
		}
		return fmt.Errorf("IMAP STARTTLS failed: %q", strings.TrimRight(line, "\r\n"))
	}
}

func negotiatePOP3(conn net.Conn) error {
	r := bufio.NewReader(conn)

	// Read greeting.
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("POP3 greeting: %w", err)
	}
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("POP3: unexpected greeting: %q", strings.TrimRight(line, "\r\n"))
	}

	// Send STLS command.
	if _, err := fmt.Fprintf(conn, "STLS\r\n"); err != nil {
		return fmt.Errorf("POP3 STLS: %w", err)
	}

	// Read response.
	line, err = r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("POP3 STLS response: %w", err)
	}
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("POP3 STLS failed: %q", strings.TrimRight(line, "\r\n"))
	}

	return nil
}

// negotiateLDAP sends an LDAP Extended Request for STARTTLS
// (OID 1.3.6.1.4.1.1466.20037) and reads the response.
func negotiateLDAP(conn net.Conn) error {
	const startTLSOID = "1.3.6.1.4.1.1466.20037"

	// Build ExtendedRequest: SEQUENCE { MessageID(1), APPLICATION(23) { OID } }
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "MessageID"))

	extReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 23, nil, "Extended Request")
	extReq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, startTLSOID, "OID"))
	packet.AppendChild(extReq)

	if _, err := conn.Write(packet.Bytes()); err != nil {
		return fmt.Errorf("LDAP STARTTLS request: %w", err)
	}

	// Read and decode the response.
	resp, err := ber.ReadPacket(conn)
	if err != nil {
		return fmt.Errorf("LDAP STARTTLS response: %w", err)
	}

	// Response: SEQUENCE { MessageID, ExtendedResponse(APPLICATION 24) { resultCode, ... } }
	if len(resp.Children) < 2 {
		return fmt.Errorf("LDAP: malformed response")
	}
	extResp := resp.Children[1]
	if extResp.Tag != 24 {
		return fmt.Errorf("LDAP: unexpected response tag %d", extResp.Tag)
	}
	if len(extResp.Children) < 1 {
		return fmt.Errorf("LDAP: malformed extended response")
	}

	resultCode, ok := extResp.Children[0].Value.(int64)
	if !ok || resultCode != 0 {
		return fmt.Errorf("LDAP STARTTLS failed: result code %v", extResp.Children[0].Value)
	}

	return nil
}
