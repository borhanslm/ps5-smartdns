# PS5 Smart DNS

Smart DNS for PlayStation 5 (and other consoles / PCs) that opens region-blocked games,
with a web panel for multiple users (shared / subscription use).

[فارسی](README.fa.md)

## How it works

```
                       Iran server                          Foreign server
PS5 ──DNS 53──► dnsmasq (+ web panel)
PS5 ──HTTPS──► Xray (reads SNI) ──VLESS Reality tunnel──► Xray ──► game server
```

- Only domains in the list (PlayStation, EA, Activision, Epic, Ubisoft, Rockstar...) go through the tunnel.
  Everything else resolves normally and goes direct.
- Traffic is not decrypted, so no certificates are needed.
- Only users you add in the panel can use the DNS (per-IP firewall). This blocks DNS abuse.

## Install (one line, Ubuntu 22.04 / 24.04, as root)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/borhanslm/ps5-smartdns/main/install.sh)
```

Run it on **both servers**, foreign first:

1. **Foreign server** (outside Iran): choose `1`. At the end it prints a link like `ps5dns://...`. Copy it.
2. **Iran server**: choose `2` and paste the link. At the end it prints the panel URL, username and password.

If you only have one server outside Iran, choose `3` (single server, no tunnel).

If `raw.githubusercontent.com` does not open from your server:

```bash
git clone https://github.com/borhanslm/ps5-smartdns.git /opt/ps5-smartdns && bash /opt/ps5-smartdns/install.sh
```

Optional, non-interactive: `ROLE=foreign IRAN_IP=1.2.3.4` (443 open only to the Iran server),
`ROLE=iran LINK=ps5dns://...`, `PANEL_PORT=2053`.
If the foreign server already runs a website on 443, use `TUNNEL_PORT=8443 NO_FIREWALL=1`.

## Panel

`http://IRAN_SERVER_IP:2053/<secret-path>/`. The path is random and shown at install time (`ps5dns login`).

- **Users**: add a user with a number of days (0 = never expires) and a maximum number of IPs.
  Use *Copy link* and send the link to the user.
- **The user** opens the link on the same internet as their console and taps **Register this network**.
  Their IP is allowed right away. If their IP changes, they open the link again.
- Extend, disable, delete, clear IPs, or add an IP by hand.
- **Domains**: edit the routed domain list; it applies immediately.
- **Settings**: server IP, admin password, open mode.

## PS5 setup

Settings → Network → Settings → Set Up Internet Connection → your connection → Advanced Settings →
DNS Settings **Manual** → Primary and Secondary = **Iran server IP**.

The same DNS works on Xbox, Nintendo Switch, PC and phones.

## Commands

| Command | |
|---|---|
| `ps5dns login` | show the panel URL and login |
| `ps5dns reset-password` | new admin password |
| `ps5dns link` | show the tunnel link again (foreign server) |
| `ps5dns logs` / `status` / `restart` | service logs and control |
| `ps5dns update` | pull the latest version |
| `ps5dns uninstall` | remove everything |

## Limitations

- Only HTTP/HTTPS (TCP 80/443) is tunneled: login, store, region checks and most matchmaking.
  In-game **UDP** traffic goes direct. If a game blocks your country during gameplay itself,
  DNS is not enough and you need a VPN on the router.
- Large game downloads (`dl.playstation.net`) are excluded on purpose to save bandwidth.
- The panel is plain HTTP. Change the admin password after install and keep the panel path private.
