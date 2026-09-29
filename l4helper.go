package caddy_wg

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4proxy"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type WGLayer4Helper struct {
	DstIface   string
	DstAddress string
	address    *caddy.NetworkAddress
	ctx        caddy.Context
	log        *zap.Logger
}

func (WGLayer4Helper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "layer4.handlers.proxy_wg", New: func() caddy.Module { return new(WGLayer4Helper) }}
}

func (w *WGLayer4Helper) Handle(downstream *layer4.Connection, _ layer4.Handler) error {
	if downstream.LocalAddr().Network() != w.address.Network {
		return fmt.Errorf("cant proxy %s to %s", downstream.LocalAddr().Network(), w.address.Network)
	}

	var stack *netstack.Net

	if app, err := w.ctx.App("wireguard"); err != nil {
		return err
	} else if wg, ok := app.(*Wireguard); !ok {
		return fmt.Errorf("failed to get active wireguard instance")
	} else if vnet, ok := wg.VNets[w.DstIface]; !ok {
		return fmt.Errorf("invalid vnet %s", w.DstIface)
	} else {
		stack = vnet.tnet
	}

	upstream, err := stack.Dial(w.address.Network, w.address.JoinHostPort(0))

	w.log.Debug("dial upstream",
		zap.String("vnet", w.DstIface),
		zap.String("remote", downstream.RemoteAddr().String()),
		zap.String("upstream", w.address.JoinHostPort(0)),
		zap.Error(err),
	)

	if err != nil {
		return err
	}

	return doProxy(downstream.Conn, upstream)
}

func (w *WGLayer4Helper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()

	if !d.NextArg() {
		return d.ArgErr()
	}

	w.DstIface = d.Val()

	if !d.NextArg() {
		return d.ArgErr()
	}

	w.DstAddress = d.Val()

	return nil
}

func parseAddress(addr string) (*caddy.NetworkAddress, error) {
	address, err := caddy.ParseNetworkAddress(addr)
	if err != nil {
		return nil, err
	}

	if address.PortRangeSize() != 1 {
		return nil, fmt.Errorf("%s: port ranges are currently not supported", addr)
	}
	return &address, nil
}

func (w *WGLayer4Helper) Provision(c caddy.Context) error {
	w.ctx = c
	w.log = c.Logger()
	addr, err := parseAddress(w.DstAddress)

	if err != nil {
		return err
	}

	w.address = addr

	return nil
}

var (
	_ caddy.Provisioner     = (*WGLayer4Helper)(nil)
	_ caddyfile.Unmarshaler = (*WGLayer4Helper)(nil)
	_ layer4.NextHandler    = (*WGLayer4Helper)(nil)
)
