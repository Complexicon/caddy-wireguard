package caddy_wg

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"golang.zx2c4.com/wireguard/conn"
)

func (v *VNet) SetMark(mark uint32) error {
	return fmt.Errorf("socket marks unsupported")
}

func (v *VNet) BatchSize() int {
	return 1
}

func (v *VNet) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.socket == nil {
		return nil
	}

	err := v.socket.Close()
	v.socket = nil
	return err
}

func (v *VNet) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {

	v.mu.Lock()
	defer v.mu.Unlock()

	curSock := v.socket

	if curSock != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	var actualPort uint16

	if addr, err := caddy.ParseNetworkAddress(fmt.Sprintf("udp/:%d", port)); err != nil {
		return nil, 0, err
	} else if caddyLsnr, err := addr.Listen(v.app.ctx, 0, net.ListenConfig{}); err != nil {
		return nil, 0, err
	} else if socket, ok := caddyLsnr.(net.PacketConn); !ok {
		return nil, 0, fmt.Errorf("unexpected listener type")
	} else if local, ok := socket.LocalAddr().(*net.UDPAddr); !ok {
		socket.Close()
		return nil, 0, fmt.Errorf("unexpected local address type %T", socket.LocalAddr())
	} else {
		actualPort = uint16(local.Port)
		v.socket = socket
	}

	socket := v.socket

	receive := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for i := range bufs {
			if n, addr, err := socket.ReadFrom(bufs[i]); err != nil {
				return 0, err
			} else if addr, err := netip.ParseAddrPort(addr.String()); err != nil {
				return 0, err
			} else {
				eps[i] = &conn.StdNetEndpoint{AddrPort: addr}
				sizes[i] = n
			}
		}

		return len(bufs), nil
	}

	return []conn.ReceiveFunc{receive}, actualPort, nil
}

func (v *VNet) ParseEndpoint(s string) (conn.Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: e}, nil
}

func (v *VNet) Send(bufs [][]byte, ep conn.Endpoint) error {
	v.mu.RLock()
	socket := v.socket
	v.mu.RUnlock()

	if socket == nil {
		return net.ErrClosed
	}

	stdEndpoint, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	addr := net.UDPAddrFromAddrPort(stdEndpoint.AddrPort)

	for _, buf := range bufs {
		if _, err := socket.WriteTo(buf, addr); err != nil {
			return err
		}
	}

	return nil
}
