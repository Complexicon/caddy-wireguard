# caddy-wireguard

A Caddy module that exposes WireGuard-backed virtual networks and lets Caddy route traffic through them. It registers custom listener networks (`wg`, `wg+tcp`, `wg+udp`) and a layer-4 helper named `proxy_wg` so you can bind services to a virtual WireGuard interface and forward connections to a peer.

This project is useful when you want Caddy to serve or proxy traffic as if it were running on an in-memory WireGuard interface, while still using the normal Caddyfile and Caddy networking model.

## Features

- Creates one or more WireGuard virtual networks using `wireguard { ... }`
- Attaches each vnet to a private IP and sets up WireGuard peer definitions
- Exposes network listeners through `wg`, `wg+tcp`, and `wg+udp`
- Supports HTTP and layer-4 routing through WireGuard peers via `proxy_wg`
- Allows Caddy to bind sites to a vnet with `bind "" wg/tun0` patterns

## Example Caddyfile

```caddyfile
{
    debug
    admin off
    skip_install_trust
    auto_https disable_redirects

    wireguard {
        vnet tun0 {
            private_key "mA0HtmCk07swY8Uxft/dAYQ6FXKf1cwsk7Wska7Me2k="
            ip 10.0.0.2

            peer {
                public_key "2CqqDrfH6I15EoGF/5YPZSTEy8hF1fO0Gf+VhVGabl8="
                ip 10.0.0.1
                keepalive 25
                endpoint 192.168.5.56:51820
            }
        }
    }

    layer4 {
        tcp/:2200 {
            route {
                proxy_wg tun0 10.0.0.1:2202
            }
        }
        tcp/:8080 {
            route {
                proxy_wg tun0 10.0.0.1:80
            }
        }
    }
}

http://:8000 {
    bind "" wg/tun0
    respond "test"
}
```

## Configuration reference

The global `wireguard` block creates one or more virtual networks:

```caddyfile
wireguard {
    vnet <name> {
        private_key <base64 key>
        ip <virtual-ip>
        listen_port <port>       # optional

        peer {
            public_key <base64 key>
            ip <peer-ip>
            psk <base64 key>       # optional
            endpoint <host:port>   # optional
            keepalive <seconds>     # optional
            alias <name>           # optional, currently informational
        }
    }
}
```

### Fields

- `private_key`: private key for the local vnet
- `ip`: the virtual address assigned to the vnet
- `listen_port`: optional UDP port to expose for the interface
- `peer.public_key`: WireGuard peer public key
- `peer.ip`: peer IP inside the virtual network
- `peer.endpoint`: remote WireGuard endpoint
- `peer.keepalive`: persistent keepalive interval in seconds
- `peer.psk`: optional pre-shared key

## Layer-4 proxying

This repo also defines a `proxy_wg` helper for `caddy-l4`:

```caddyfile
layer4 {
    tcp/:443 {
        route {
            proxy_wg tun0 10.0.0.1:443
        }
    }
}
```

`proxy_wg` dials the target address through the selected vnet and copies traffic between the downstream client connection and the upstream WireGuard peer connection.

## Building

This module is intended to be compiled into a custom Caddy binary. Typical usage is through `xcaddy` or by importing the module in a Go-based Caddy build.

```bash
xcaddy build --with github.com/Complexicon/caddy-wireguard
```

Then start Caddy with your configured Caddyfile.

## Notes

This project is still experimental. The repository includes a `todos.md` file with follow-up work such as improving the slop proxy implementation and adding additional routing behavior. For production use, test carefully and verify WireGuard peer and network semantics in your environment.

## License

This project does not currently declare a license file in the repository snapshot. Check the repository for the canonical licensing terms before using it in production.

## Repository status

This repo is a Go project (`module caddy-wg`) built around Caddy v2 and WireGuard (`golang.zx2c4.com/wireguard`).
