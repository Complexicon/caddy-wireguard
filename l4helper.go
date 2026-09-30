package caddy_wg

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"

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
	alias      string
	port       uint16
	address    netip.Addr
	ctx        caddy.Context
	log        *zap.Logger
}

var (
	_ caddy.Provisioner     = (*WGLayer4Helper)(nil)
	_ caddyfile.Unmarshaler = (*WGLayer4Helper)(nil)
	_ layer4.NextHandler    = (*WGLayer4Helper)(nil)
)

func (WGLayer4Helper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "layer4.handlers.proxy_wg", New: func() caddy.Module { return new(WGLayer4Helper) }}
}

func (w *WGLayer4Helper) Handle(downstream *layer4.Connection, _ layer4.Handler) error {
	var stack *netstack.Net
	var dst netip.Addr

	if app, err := w.ctx.App("wireguard"); err != nil {
		return err
	} else if wg, ok := app.(*Wireguard); !ok {
		return fmt.Errorf("failed to get active wireguard instance")
	} else if vnet, ok := wg.VNets[w.DstIface]; !ok {
		return fmt.Errorf("invalid vnet %s", w.DstIface)
	} else {
		stack = vnet.Netstack()
		dst = w.address

		if len(w.alias) > 0 {
			if dst, err = vnet.IPByAlias(w.alias); err != nil {
				return fmt.Errorf("invalid destination alias %s @ %s", w.alias, vnet.Name)
			}
		}

	}

	upstreamAddr := netip.AddrPortFrom(dst, w.port).String()
	upstream, err := stack.Dial(downstream.LocalAddr().Network(), upstreamAddr)

	w.log.Debug("dial upstream",
		zap.String("vnet", w.DstIface),
		zap.String("remote", downstream.RemoteAddr().String()),
		zap.String("upstream", upstreamAddr),
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
	host, port, err := net.SplitHostPort(w.DstAddress)

	if err != nil {
		return err
	}

	if w.address, err = netip.ParseAddr(host); err != nil {
		w.alias = host // assume host part refers to an alias if ip parsing fails
	}

	if n, err := strconv.Atoi(port); err != nil {
		return err
	} else {
		w.port = uint16(n)
	}

	return nil
}
