package caddy_wg

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Peer struct {
	Alias        string
	PublicKey    string
	IP           string
	PreSharedKey string
	Endpoint     string
	KeepAlive    int
}

type VNet struct {
	socket     net.PacketConn
	mu         sync.RWMutex
	app        *Wireguard
	dev        *device.Device
	tun        tun.Device
	tnet       *netstack.Net
	log        *zap.SugaredLogger
	Peers      []Peer
	PrivateKey string
	IP         string
	ListenPort uint16
}

type Wireguard struct {
	ctx   caddy.Context
	VNets map[string]*VNet
}

func init() {
	caddy.RegisterNetwork("wg", mkWGListener("tcp"))
	caddy.RegisterNetwork("wg+tcp", mkWGListener("tcp"))
	caddy.RegisterNetwork("wg+udp", mkWGListener("udp"))

	caddy.RegisterModule(Wireguard{})
	caddy.RegisterModule(WGLayer4Helper{})

	caddyhttp.RegisterNetworkHTTP3("wg", "wg+udp")
	caddyhttp.RegisterNetworkHTTP3("wg+tcp", "wg+udp")

	httpcaddyfile.RegisterGlobalOption("wireguard", parseCfg)
}

func (Wireguard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "wireguard", New: func() caddy.Module { return new(Wireguard) }}
}

func (w *Wireguard) Provision(c caddy.Context) error {
	w.ctx = c

	for name, v := range w.VNets {
		v.log = c.Logger().Sugar().Named(name)
		v.app = w
		v.log.Info("provisioning...")

		ip, err := netip.ParseAddr(v.IP)
		if err != nil {
			return err
		}

		v.tun, v.tnet, err = netstack.CreateNetTUN([]netip.Addr{ip}, nil, 1280)
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *Wireguard) Start() error {
	for _, w := range w.VNets {
		w.log.Info("starting wireguard")

		w.dev = device.NewDevice(w.tun, w, &device.Logger{
			Verbosef: func(format string, args ...any) { w.log.Debugf(format, args...) },
			Errorf:   func(format string, args ...any) { w.log.Errorf(format, args...) },
		})

		u := new(uapiHelper)

		u.Add("private_key", b64tohex(w.PrivateKey))
		u.Add("replace_peers", "true")

		if w.ListenPort != 0 {
			u.Add("listen_port", strconv.Itoa(int(w.ListenPort)))
		}

		for _, p := range w.Peers {
			u.Add("public_key", b64tohex(p.PublicKey))
			u.Add("allowed_ip", fmt.Sprintf("%s/32", p.IP))

			if p.Endpoint != "" {
				u.Add("endpoint", p.Endpoint)
			}

			if p.KeepAlive > 0 {
				u.Add("persistent_keepalive_interval", strconv.Itoa(p.KeepAlive))
			}

			if p.PreSharedKey != "" {
				u.Add("preshared_key", b64tohex(p.PreSharedKey))
			}
		}

		if err := w.dev.IpcSet(u.String()); err != nil {
			return err
		}

		if err := w.dev.Up(); err != nil {
			return err
		}
	}

	return nil
}

func (w *Wireguard) Stop() error {

	for _, v := range w.VNets {
		v.log.Info("stopping wireguard")
		v.dev.Close()
	}

	return nil
}

var (
	_ caddy.App         = (*Wireguard)(nil)
	_ caddy.Provisioner = (*Wireguard)(nil)
	_ conn.Bind         = (*VNet)(nil)
)
