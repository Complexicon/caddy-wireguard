package caddy_wg

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func mkWGListener(protocol string) caddy.ListenerFunc {
	return func(ctx context.Context, network, host, portRange string, portOffset uint, cfg net.ListenConfig) (any, error) {

		var stack *netstack.Net
		var ip string

		if ctx, ok := ctx.(caddy.Context); !ok {
			return nil, fmt.Errorf("failed to get caddy context")
		} else if app, err := ctx.App("wireguard"); err != nil {
			return nil, err
		} else if wg, ok := app.(*Wireguard); !ok {
			return nil, fmt.Errorf("failed to get active wireguard instance")
		} else if vnet, ok := wg.VNets[host]; !ok {
			return nil, fmt.Errorf("invalid vnet %s", host)
		} else {
			stack = vnet.tnet
			ip = vnet.IP
		}

		na, err := caddy.ParseNetworkAddress(caddy.JoinNetworkAddress(protocol, host, portRange))
		if err != nil {
			return nil, err
		}

		addr := na.JoinHostPort(portOffset)

		_, _, port, err := caddy.SplitNetworkAddress(addr)
		if err != nil {
			return nil, err
		}

		var lsnr any

		switch protocol {
		case "tcp":
			lsnr, err = stack.ListenTCPAddrPort(netip.MustParseAddrPort(net.JoinHostPort(ip, port)))
		case "udp":
			lsnr, err = stack.ListenUDPAddrPort(netip.MustParseAddrPort(net.JoinHostPort(ip, port)))
		}

		if err != nil {
			return nil, err
		}

		return lsnr, nil
	}
}
