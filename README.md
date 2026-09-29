# caddy-wireguard

A Caddy module that exposes WireGuard-backed virtual networks and lets Caddy route traffic through them, because why not :)

## Features

- Create one or more WireGuard virtual networks
- Fully integrates with other "full"-featured Wireguard peers
- Exposes network custom listeners through `wg`/`wg+tcp` and `wg+udp`
- Supports HTTP and layer-4 routing through WireGuard peers via `proxy_wg`
- Allows Caddy to bind sites to a vnet with `bind wg/<vnet name>`
- (ab)use as a replacement for cloudflare tunnels

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

This project is a toy project and experimental, a lot of use cases were hand tested and work but those that werent tested probably wont

## thanks

This project wouldnt be possible without Caddy and WireGuard (`golang.zx2c4.com/wireguard`).
