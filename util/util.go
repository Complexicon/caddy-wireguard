package util

import (
	"encoding/base64"
	"encoding/hex"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func IsValidKey(s string) bool {
	if len(s) != base64.StdEncoding.EncodedLen(32) {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(decoded) != 32 {
		return false
	}

	return base64.StdEncoding.EncodeToString(decoded) == s
}

func MustB64toHex(b string) string {
	v, _ := base64.StdEncoding.DecodeString(b)
	return hex.EncodeToString(v)
}

func ParseArg[T any](d *caddyfile.Dispenser, arg *T) error {
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
