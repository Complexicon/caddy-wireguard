package caddy_wg

import (
	"net/netip"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func getArg[T any](d *caddyfile.Dispenser, arg *T) error {
	if !d.NextArg() {
		return d.ArgErr()
	}

	if val, ok := d.ScalarVal().(T); ok {
		*arg = val
	} else {
		return d.Errf("bad cast %s", d.Val())
	}

	return nil
}

func parseCfg(d *caddyfile.Dispenser, existingVal any) (any, error) {
	w := &Wireguard{
		VNets: map[string]*VNet{},
	}

	if existingVal != nil {
		return nil, d.ArgErr()
	}

	d.Next()

	if d.CountRemainingArgs() > 0 {
		return nil, d.ArgErr()
	}

	for d.NextBlock(0) {
		if d.Val() != "vnet" {
			return nil, d.ArgErr()
		}

		if !d.NextArg() {
			return nil, d.ArgErr()
		}

		name := d.Val()

		vnet := &VNet{}

		d.Next()

		if !d.NextBlock(0) {
			return nil, d.ArgErr()
		}

		for {
			switch d.Val() {
			case "private_key":
				if err := getArg(d, &vnet.PrivateKey); err != nil {
					return nil, err
				}
			case "ip":
				if err := getArg(d, &vnet.IP); err != nil {
					return nil, err
				}
			case "listen_port":
				var n int
				if err := getArg(d, &n); err != nil {
					return nil, err
				}
				vnet.ListenPort = uint16(n)
			case "peer":

				d.Next()

				if !d.NextBlock(0) {
					return nil, d.ArgErr()
				}

				p := Peer{}

				for {
					switch d.Val() {
					case "public_key":
						if err := getArg(d, &p.PublicKey); err != nil {
							return nil, err
						}
					case "psk":
						if err := getArg(d, &p.PreSharedKey); err != nil {
							return nil, err
						}
					case "alias":
						if err := getArg(d, &p.Alias); err != nil {
							return nil, err
						}
					case "ip":
						if err := getArg(d, &p.IP); err != nil {
							return nil, err
						}

						if _, err := netip.ParseAddr(d.Val()); err != nil {
							return nil, err
						}

					case "endpoint":
						if err := getArg(d, &p.Endpoint); err != nil {
							return nil, err
						}

					case "keepalive":
						if err := getArg(d, &p.KeepAlive); err != nil {
							return nil, err
						}
					default:
						return nil, d.Errf("unknown subdirective %q", d.Val())
					}

					if !d.NextBlock(0) {
						break
					}
				}

				vnet.Peers = append(vnet.Peers, p)
			default:
				return nil, d.Errf("unknown subdirective %q", d.Val())
			}

			if !d.NextBlock(0) {
				break
			}
		}

		w.VNets[name] = vnet
	}

	return httpcaddyfile.App{
		Name:  "wireguard",
		Value: caddyconfig.JSON(w, nil),
	}, nil
}
