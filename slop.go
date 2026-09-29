package caddy_wg

import (
	"errors"
	"io"
	"net"
	"sync"
)

//
// TODO: rewrite this slop implementation to be actually decent.
//

func doProxy(a, b net.Conn) error {
	aTCP := isTCP(a)
	bTCP := isTCP(b)

	aUDP := isUDP(a)
	bUDP := isUDP(b)

	// Only TCP <-> TCP or UDP <-> UDP is supported.
	if !((aTCP && bTCP) || (aUDP && bUDP)) {
		return errors.New("proxy: connections must both be TCP or both be UDP")
	}

	tcp := aTCP && bTCP

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	wg.Add(2)

	// a -> b
	go func() {
		defer wg.Done()
		errCh <- proxyDirection(b, a, tcp)
	}()

	// b -> a
	go func() {
		defer wg.Done()
		errCh <- proxyDirection(a, b, tcp)
	}()

	// Wait for the first direction to finish.
	firstErr := <-errCh

	if tcp && firstErr == nil {
		// A TCP half-close has occurred. The other direction may
		// still have data to send, so leave both connections open.
	} else {
		// UDP has no half-close semantics, and a real error means
		// the proxy should terminate both directions.
		_ = a.Close()
		_ = b.Close()
	}

	// Wait for the other direction.
	secondErr := <-errCh

	_ = a.Close()
	_ = b.Close()

	if firstErr != nil {
		return firstErr
	}

	return secondErr
}

func proxyDirection(dst, src net.Conn, tcp bool) error {
	_, err := io.Copy(dst, src)

	// Normal EOF is not an error.
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	if tcp {
		// Propagate the EOF as a TCP FIN on the destination.
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			return c.CloseWrite()
		}
	}

	return nil
}

func isTCP(c net.Conn) bool {
	return c.LocalAddr().Network() == "tcp"
}

func isUDP(c net.Conn) bool {
	return c.LocalAddr().Network() == "udp"
}
