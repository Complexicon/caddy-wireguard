package caddy_wg

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/Complexicon/caddy-wireguard/vnet"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type Wireguard struct {
	VNets map[string]*vnet.VNet
}

var (
	_ caddy.App         = (*Wireguard)(nil)
	_ caddy.Provisioner = (*Wireguard)(nil)
)

func init() {
	caddy.RegisterNetwork("wg", mkWGListener("tcp"))
	caddy.RegisterNetwork("wg+tcp", mkWGListener("tcp"))
	caddy.RegisterNetwork("wg+udp", mkWGListener("udp"))

	caddy.RegisterModule(Wireguard{})
	caddy.RegisterModule(WGLayer4Helper{})

	caddyhttp.RegisterNetworkHTTP3("wg", "wg+udp")
	caddyhttp.RegisterNetworkHTTP3("wg+tcp", "wg+udp")

	httpcaddyfile.RegisterGlobalOption("wireguard", func(d *caddyfile.Dispenser, existingVal any) (any, error) {
		w := &Wireguard{VNets: map[string]*vnet.VNet{}}

		if existingVal != nil {
			return nil, d.ArgErr()
		}

		d.Next() // consume "wireguard" directive

		if d.NextArg() {
			return nil, d.ArgErr()
		}

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			if d.Val() != "vnet" {
				return nil, d.ArgErr()
			}

			net := &vnet.VNet{}

			if err := net.UnmarshalCaddyfile(d); err != nil {
				return nil, err
			}

			w.VNets[net.Name] = net
		}

		return httpcaddyfile.App{Name: "wireguard", Value: caddyconfig.JSON(w, nil)}, nil
	})
}

func (Wireguard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "wireguard", New: func() caddy.Module { return new(Wireguard) }}
}

func (w *Wireguard) Provision(c caddy.Context) error {
	for _, vnet := range w.VNets {
		if err := vnet.Provision(c); err != nil {
			return err
		}
	}
	return nil
}

func (w *Wireguard) Start() error {
	for _, vnet := range w.VNets {
		if err := vnet.Up(); err != nil {
			return err
		}
	}
	return nil
}

func (w *Wireguard) Stop() error {
	for _, vnet := range w.VNets {
		vnet.Down()
	}
	return nil
}

func mkWGListener(protocol string) caddy.ListenerFunc {
	return func(ctx context.Context, network, host, portRange string, portOffset uint, cfg net.ListenConfig) (any, error) {

		vnet, err := getVNet(ctx, host)
		if err != nil {
			return nil, err
		}

		stack := vnet.Netstack()
		ip := vnet.IP

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

func getVNet(ctx context.Context, name string) (*vnet.VNet, error) {
	if ctx, ok := ctx.(caddy.Context); !ok {
		return nil, fmt.Errorf("failed to get caddy context")
	} else if app, err := ctx.App("wireguard"); err != nil {
		return nil, err
	} else if wg, ok := app.(*Wireguard); !ok {
		return nil, fmt.Errorf("failed to get active wireguard instance")
	} else if vnet, ok := wg.VNets[name]; !ok {
		return nil, fmt.Errorf("invalid vnet %s", name)
	} else {
		return vnet, nil
	}
}
