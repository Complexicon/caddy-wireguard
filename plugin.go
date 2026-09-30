package caddy_wg

import (
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
