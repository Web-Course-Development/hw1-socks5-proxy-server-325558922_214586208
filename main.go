package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
)

// SOCKS protocol constants (RFC 1928 / RFC 1929).
const (
	socksVersion = 0x05

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF

	authVersion   = 0x01 // username/password sub-negotiation version
	authSuccess   = 0x00
	authFailure   = 0x01

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded          = 0x00
	repGeneralFailure     = 0x01
	repHostUnreachable    = 0x04
	repConnectionRefused  = 0x05
	repCommandNotSupported = 0x07
	repAddrNotSupported   = 0x08
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// 1. Read client greeting and negotiate authentication method.
	method, err := negotiateAuth(conn)
	if err != nil {
		log.Printf("auth negotiation failed: %v", err)
		return
	}

	// 2. Perform username/password authentication if it was selected.
	if method == methodUserPass {
		if err := authenticateUserPass(conn); err != nil {
			log.Printf("authentication failed: %v", err)
			return
		}
	}

	// 3-5. Read CONNECT request, dial target, send reply.
	target, err := handleConnect(conn)
	if err != nil {
		log.Printf("connect failed: %v", err)
		return
	}
	defer target.Close()

	// 6. Relay data between client and target.
	relay(conn, target)
}

// negotiateAuth reads the client greeting and writes the method selection.
// It returns the method that was selected.
func negotiateAuth(conn net.Conn) (byte, error) {
	// VER, NMETHODS
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, fmt.Errorf("read greeting header: %w", err)
	}
	if header[0] != socksVersion {
		return 0, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, fmt.Errorf("read methods: %w", err)
	}

	// Decide which method we require based on whether auth is configured.
	authRequired := os.Getenv("PROXY_USER") != ""
	want := byte(methodNoAuth)
	if authRequired {
		want = methodUserPass
	}

	for _, m := range methods {
		if m == want {
			if _, err := conn.Write([]byte{socksVersion, want}); err != nil {
				return 0, fmt.Errorf("write method selection: %w", err)
			}
			return want, nil
		}
	}

	// No acceptable method offered.
	if _, err := conn.Write([]byte{socksVersion, methodNoAcceptable}); err != nil {
		return 0, fmt.Errorf("write no-acceptable-method: %w", err)
	}
	return 0, fmt.Errorf("no acceptable authentication method")
}

// authenticateUserPass performs the RFC 1929 username/password sub-negotiation.
// Note: the sub-negotiation version is 0x01, not 0x05.
func authenticateUserPass(conn net.Conn) error {
	// VER, ULEN
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read auth header: %w", err)
	}
	if header[0] != authVersion {
		return fmt.Errorf("unsupported auth version: %d", header[0])
	}

	uLen := int(header[1])
	username := make([]byte, uLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("read username: %w", err)
	}

	// PLEN
	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}
	password := make([]byte, int(pLenBuf[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if string(username) == expectedUser && string(password) == expectedPass {
		if _, err := conn.Write([]byte{authVersion, authSuccess}); err != nil {
			return fmt.Errorf("write auth success: %w", err)
		}
		return nil
	}

	// Reject invalid credentials.
	if _, err := conn.Write([]byte{authVersion, authFailure}); err != nil {
		return fmt.Errorf("write auth failure: %w", err)
	}
	return fmt.Errorf("invalid credentials for user %q", string(username))
}

// handleConnect reads the CONNECT request, dials the target, sends the reply,
// and returns the connection to the target on success.
func handleConnect(conn net.Conn) (net.Conn, error) {
	// VER, CMD, RSV, ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("read request header: %w", err)
	}
	if header[0] != socksVersion {
		sendReply(conn, repGeneralFailure)
		return nil, fmt.Errorf("unsupported version in request: %d", header[0])
	}
	if header[1] != cmdConnect {
		sendReply(conn, repCommandNotSupported)
		return nil, fmt.Errorf("unsupported command: %d", header[1])
	}

	atyp := header[3]
	var host string

	switch atyp {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("read IPv4 address: %w", err)
		}
		host = net.IP(addr).String()
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, fmt.Errorf("read domain: %w", err)
		}
		host = string(domain)
	case atypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("read IPv6 address: %w", err)
		}
		host = net.IP(addr).String()
	default:
		sendReply(conn, repAddrNotSupported)
		return nil, fmt.Errorf("unsupported address type: %d", atyp)
	}

	// PORT (big-endian uint16)
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		sendReply(conn, repHostUnreachable)
		return nil, fmt.Errorf("dial target %s:%d: %w", host, port, err)
	}

	if err := sendReply(conn, repSucceeded); err != nil {
		target.Close()
		return nil, fmt.Errorf("write success reply: %w", err)
	}
	return target, nil
}

// sendReply writes a SOCKS5 reply with the given REP code. BND.ADDR/BND.PORT
// are reported as IPv4 0.0.0.0:0, which is acceptable for CONNECT.
func sendReply(conn net.Conn, rep byte) error {
	reply := []byte{
		socksVersion, rep, 0x00, atypIPv4,
		0x00, 0x00, 0x00, 0x00, // BND.ADDR = 0.0.0.0
		0x00, 0x00, // BND.PORT = 0
	}
	_, err := conn.Write(reply)
	return err
}

// relay copies data in both directions between client and target until either
// side closes. CloseWrite signals EOF on the half that finished so the peer's
// read returns and HTTP responses terminate cleanly.
func relay(client, target net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(target, client)
		if c, ok := target.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
		done <- struct{}{}
	}()

	go func() {
		io.Copy(client, target)
		if c, ok := client.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}
