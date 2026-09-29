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

	for name, vnet := range w.VNets {
		vnet.log = c.Logger().Sugar().Named(name)
		vnet.app = w
		vnet.log.Info("provisioning...")

		ip, err := netip.ParseAddr(vnet.IP)
		if err != nil {
			return err
		}

		vnet.tun, vnet.tnet, err = netstack.CreateNetTUN([]netip.Addr{ip}, nil, 1280)
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *Wireguard) Start() error {
	for _, vnet := range w.VNets {
		vnet.log.Info("starting wireguard")

		vnet.dev = device.NewDevice(vnet.tun, vnet, &device.Logger{
			Verbosef: func(format string, args ...any) { vnet.log.Debugf(format, args...) },
			Errorf:   func(format string, args ...any) { vnet.log.Errorf(format, args...) },
		})

		uapi := new(uapiHelper)

		uapi.Add("private_key", b64tohex(vnet.PrivateKey))
		uapi.Add("replace_peers", "true")

		if vnet.ListenPort != 0 {
			uapi.Add("listen_port", strconv.Itoa(int(vnet.ListenPort)))
		}

		for _, peer := range vnet.Peers {
			uapi.Add("public_key", b64tohex(peer.PublicKey))
			uapi.Add("allowed_ip", fmt.Sprintf("%s/32", peer.IP))

			if peer.Endpoint != "" {
				uapi.Add("endpoint", peer.Endpoint)
			}

			if peer.KeepAlive > 0 {
				uapi.Add("persistent_keepalive_interval", strconv.Itoa(peer.KeepAlive))
			}

			if peer.PreSharedKey != "" {
				uapi.Add("preshared_key", b64tohex(peer.PreSharedKey))
			}
		}

		if err := vnet.dev.IpcSet(uapi.String()); err != nil {
			return err
		}

		if err := vnet.dev.Up(); err != nil {
			return err
		}
	}

	return nil
}

func (w *Wireguard) Stop() error {

	for _, vnet := range w.VNets {
		vnet.log.Info("stopping wireguard")
		vnet.dev.Close()
	}

	return nil
}

var (
	_ caddy.App         = (*Wireguard)(nil)
	_ caddy.Provisioner = (*Wireguard)(nil)
	_ conn.Bind         = (*VNet)(nil)
)
