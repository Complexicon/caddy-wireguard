package caddy_wg

import (
	"encoding/base64"
	"encoding/hex"
)

func b64tohex(b string) string {
	v, _ := base64.StdEncoding.DecodeString(b)
	return hex.EncodeToString(v)
}
