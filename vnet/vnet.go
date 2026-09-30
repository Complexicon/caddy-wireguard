package vnet

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/Complexicon/caddy-wireguard/util"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const DEFAULT_MTU = 1280

type VNet struct {
	socket  net.PacketConn
	mu      sync.RWMutex
	ctx     caddy.Context
	dev     *device.Device
	tun     tun.Device
	tnet    *netstack.Net
	log     *zap.SugaredLogger
	aliases map[string]string

	Peers      []*Peer
	PrivateKey string
	IP         string
	Name       string
	ListenPort uint16
}

var (
	_ caddyfile.Unmarshaler = (*VNet)(nil)
	_ caddy.Provisioner     = (*VNet)(nil)
)

func (vnet *VNet) Up() error {
	vnet.log.Info("starting vnet")

	vnet.dev = device.NewDevice(vnet.tun, vnet, &device.Logger{
		Verbosef: func(format string, args ...any) { vnet.log.Debugf(format, args...) },
		Errorf:   func(format string, args ...any) { vnet.log.Errorf(format, args...) },
	})

	uapi := util.Uapi()

	uapi.Add("private_key", util.MustB64toHex(vnet.PrivateKey))
	uapi.Add("replace_peers", "true")

	if vnet.ListenPort != 0 {
		uapi.Add("listen_port", strconv.Itoa(int(vnet.ListenPort)))
	}

	for _, peer := range vnet.Peers {
		uapi.Add("public_key", util.MustB64toHex(peer.PublicKey))
		uapi.Add("allowed_ip", fmt.Sprintf("%s/32", peer.IP))

		if peer.Endpoint != "" {
			uapi.Add("endpoint", peer.Endpoint)
		}

		if peer.KeepAlive > 0 {
			uapi.Add("persistent_keepalive_interval", strconv.Itoa(peer.KeepAlive))
		}

		if peer.PreSharedKey != "" {
			uapi.Add("preshared_key", util.MustB64toHex(peer.PreSharedKey))
		}
	}

	if err := vnet.dev.IpcSet(uapi.String()); err != nil {
		return err
	}

	if err := vnet.dev.Up(); err != nil {
		return err
	}

	return nil
}

func (vnet *VNet) Down() {
	vnet.log.Info("stopping vnet")
	vnet.dev.Close()
}

func (vnet *VNet) Netstack() *netstack.Net {
	return vnet.tnet
}

func (vnet *VNet) IPByAlias(alias string) (netip.Addr, error) {
	if ip, ok := vnet.aliases[alias]; ok {
		return netip.MustParseAddr(ip), nil
	}
	return netip.Addr{}, fmt.Errorf("alias %s not found", alias)
}

func (vnet *VNet) Provision(c caddy.Context) error {
	vnet.log = c.Logger().Sugar().Named(vnet.Name)
	vnet.ctx = c
	vnet.aliases = make(map[string]string)

	for _, p := range vnet.Peers {
		if len(p.Alias) > 0 {
			if _, exists := vnet.aliases[p.Alias]; exists {
				vnet.log.Warnf("peer with alias %s already defined", p.Alias)
			} else {
				vnet.aliases[p.Alias] = p.IP
			}
		}
	}

	var err error
	vnet.tun, vnet.tnet, err = netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(vnet.IP)}, nil, DEFAULT_MTU)
	if err != nil {
		return err
	}

	return nil
}

func (vnet *VNet) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.NextArg() {
		return d.ArgErr()
	}

	vnet.Name = d.Val()

	if d.NextArg() {
		return d.ArgErr()
	}

	nesting := d.Nesting()

	if !d.NextBlock(nesting) {
		return d.ArgErr()
	}

	for {
		switch d.Val() {
		case "private_key":
			if err := util.ParseArg(d, &vnet.PrivateKey); err != nil {
				return err
			}
		case "ip":
			if err := util.ParseArg(d, &vnet.IP); err != nil {
				return err
			}
		case "listen_port":
			var n int
			if err := util.ParseArg(d, &n); err != nil {
				return err
			}
			vnet.ListenPort = uint16(n)
		case "peer":
			peer := &Peer{}
			if err := peer.UnmarshalCaddyfile(d); err != nil {
				return err
			}
			vnet.Peers = append(vnet.Peers, peer)
		default:
			return d.Errf("unknown directive %q", d.Val())
		}

		if !d.NextBlock(nesting) {
			break
		}
	}

	if !util.IsValidKey(vnet.PrivateKey) {
		return fmt.Errorf("private_key of vnet %s is not a wireguard key", vnet.Name)
	}

	if _, err := netip.ParseAddr(vnet.IP); err != nil {
		return err
	}

	return nil
}
