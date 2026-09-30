package vnet

import (
	"fmt"
	"net/netip"

	"github.com/Complexicon/caddy-wireguard/util"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

type Peer struct {
	Alias        string
	PublicKey    string
	IP           string
	PreSharedKey string
	Endpoint     string
	KeepAlive    int
}

var _ caddyfile.Unmarshaler = (*Peer)(nil)

func (peer *Peer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if d.NextArg() {
		peer.Alias = d.Val()
	}

	nesting := d.Nesting()

	if !d.NextBlock(nesting) {
		return d.ArgErr()
	}

	for {
		switch d.Val() {
		case "public_key":
			if err := util.ParseArg(d, &peer.PublicKey); err != nil {
				return err
			}
		case "psk":
			if err := util.ParseArg(d, &peer.PreSharedKey); err != nil {
				return err
			}
		case "ip":
			if err := util.ParseArg(d, &peer.IP); err != nil {
				return err
			}
		case "endpoint":
			if err := util.ParseArg(d, &peer.Endpoint); err != nil {
				return err
			}
		case "keepalive":
			if err := util.ParseArg(d, &peer.KeepAlive); err != nil {
				return err
			}
		default:
			return d.Errf("unknown directive %q", d.Val())
		}

		if !d.NextBlock(nesting) {
			break
		}
	}

	if _, err := netip.ParseAddr(peer.IP); err != nil {
		return err
	}

	if len(peer.Endpoint) > 0 {
		if _, err := netip.ParseAddrPort(peer.Endpoint); err != nil {
			return nil
		}
	}

	if !util.IsValidKey(peer.PublicKey) {
		return fmt.Errorf("public_key '%s' is not a wireguard key", peer.PublicKey)
	}

	if len(peer.PreSharedKey) > 0 {
		if !util.IsValidKey(peer.PreSharedKey) {
			return fmt.Errorf("psk '%s' is not a wireguard key", peer.PreSharedKey)
		}
	}

	return nil
}
