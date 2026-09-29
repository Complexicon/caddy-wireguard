package caddy_wg

import "strings"

type uapiHelper [][2]string

func (u *uapiHelper) Add(key, value string) {
	*u = append(*u, [2]string{key, value})
}

func (u *uapiHelper) String() string {
	var b = strings.Builder{}
	for _, e := range *u {
		k, v := e[0], e[1]
		b.WriteString(k)
		b.WriteRune('=')
		b.WriteString(v)
		b.WriteRune('\n')
	}
	return b.String()
}
