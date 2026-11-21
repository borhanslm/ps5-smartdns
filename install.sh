#!/usr/bin/env bash
# PS5 Smart DNS installer (Ubuntu 22.04 / 24.04, run as root)
#   bash <(curl -fsSL https://raw.githubusercontent.com/borhanslm/ps5-smartdns/main/install.sh)
#
# Roles:
#   foreign : VPS outside Iran. Runs only the VLESS Reality tunnel endpoint. Install this FIRST.
#   iran    : VPS inside Iran. DNS + web panel; tunnels game traffic to the foreign server.
#   single  : one VPS outside Iran doing everything (no tunnel).
# Non-interactive: ROLE=foreign|iran|single  LINK=<link from foreign>  PANEL_PORT=2053  IRAN_IP=<ip>
#                  TUNNEL_PORT=8443 (foreign, if 443 is taken)  NO_FIREWALL=1 (leave ufw alone)
set -euo pipefail

REPO="https://github.com/borhanslm/ps5-smartdns.git"
DIR=/opt/ps5-smartdns
XRAY_VERSION="v26.10.31"
PANEL_PORT="${PANEL_PORT:-2053}"
REALITY_SNI="${REALITY_SNI:-www.microsoft.com}"
TUNNEL_PORT="${TUNNEL_PORT:-443}"   # foreign role: use another port if 443 is taken (e.g. a website)
NO_FIREWALL="${NO_FIREWALL:-0}"     # 1 = do not touch ufw (server already runs other services)

c() { printf '\033[1;36m==> %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mError: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$EUID" -eq 0 ] || die "run as root (sudo -i)"
command -v apt-get >/dev/null || die "only Ubuntu/Debian are supported"

if [ -z "${ROLE:-}" ]; then
  echo "Where is this server?"
  echo "  1) Outside Iran - tunnel endpoint (install this one first)"
  echo "  2) Inside Iran  - DNS + panel, tunnels to the foreign server"
  echo "  3) Outside Iran - single server, no tunnel"
  read -rp "Choose [1-3]: " n
  case "$n" in 1) ROLE=foreign ;; 2) ROLE=iran ;; 3) ROLE=single ;; *) die "invalid choice" ;; esac
fi

c "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y -qq
BASE="curl git unzip openssl ufw nftables ca-certificates"
case "$ROLE" in
  foreign) apt-get install -y -qq $BASE ;;
  iran|single) apt-get install -y -qq $BASE dnsmasq-base python3 python3-flask python3-waitress ;;
  *) die "ROLE must be foreign, iran or single" ;;
esac

if [ -d "$DIR/.git" ]; then git -C "$DIR" pull -q --ff-only; else git clone -q --depth 1 "$REPO" "$DIR"; fi
cd "$DIR"
ln -sf "$DIR/ps5dns" /usr/local/bin/ps5dns && chmod +x "$DIR/ps5dns"

install_xray() {
  # skip only if the pinned version is already installed (otherwise install / upgrade)
  if command -v xray >/dev/null && xray version 2>/dev/null | head -1 | grep -q "Xray ${XRAY_VERSION#v} "; then return; fi
  c "Installing Xray $XRAY_VERSION"
  case "$(uname -m)" in
    x86_64) A=64 ;; aarch64) A=arm64-v8a ;; *) die "unsupported CPU $(uname -m)" ;;
  esac
  T=$(mktemp -d)
  curl -fsSL -o "$T/x.zip" "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-linux-$A.zip" \
    || die "could not download Xray from GitHub"
  unzip -q -o "$T/x.zip" -d "$T" && install -m 755 "$T/xray" /usr/local/bin/xray
  mkdir -p /usr/local/share/xray && cp "$T"/*.dat /usr/local/share/xray/ 2>/dev/null || true
  rm -rf "$T"
}

SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port /{print $2}' | head -1 || true); SSH_PORT=${SSH_PORT:-22}
MYIP=$(curl -4 -fsS --max-time 10 https://api.ipify.org || hostname -I | awk '{print $1}')

# ------------------------------------------------------------------ foreign
if [ "$ROLE" = foreign ]; then
  if [ ! -f "$DIR/tunnel-link.txt" ] && ss -tln | awk '{print $4}' | grep -qE "[:.]$TUNNEL_PORT\$"; then
    die "port $TUNNEL_PORT is already in use. Re-run with another port, e.g. TUNNEL_PORT=8443"
  fi
  install_xray
  mkdir -p /usr/local/etc/xray
  if [ ! -f "$DIR/tunnel-link.txt" ]; then
    UUID=$(xray uuid)
    KEYS=$(xray x25519)
    PRIV=$(echo "$KEYS" | awk -F': *' '/^Private/{print $2}')
    PUB=$(echo "$KEYS" | awk -F': *' '/^Public key|^Password/{print $2}')
    SID=$(openssl rand -hex 8)
    [ -n "$PRIV" ] && [ -n "$PUB" ] || die "could not generate Reality keys"
    cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": $TUNNEL_PORT, "protocol": "vless",
    "settings": {"clients": [{"id": "$UUID", "flow": "xtls-rprx-vision"}], "decryption": "none"},
    "streamSettings": {"network": "tcp", "security": "reality",
      "realitySettings": {"dest": "$REALITY_SNI:443", "serverNames": ["$REALITY_SNI"],
                          "privateKey": "$PRIV", "shortIds": ["$SID"]}}
  }],
  "outbounds": [{"protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}}]
}
EOF
    JSON="{\"ip\":\"$MYIP\",\"port\":$TUNNEL_PORT,\"uuid\":\"$UUID\",\"pbk\":\"$PUB\",\"sid\":\"$SID\",\"sni\":\"$REALITY_SNI\"}"
    echo "ps5dns://$(printf %s "$JSON" | base64 -w0)" > "$DIR/tunnel-link.txt"
    chmod 600 "$DIR/tunnel-link.txt"
  fi
  cat > /etc/systemd/system/ps5dns-xray.service <<EOF
[Unit]
Description=PS5 Smart DNS tunnel endpoint (Xray)
After=network-online.target
[Service]
ExecStart=/usr/local/bin/xray run -c /usr/local/etc/xray/config.json
Restart=always
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload && systemctl enable --now ps5dns-xray >/dev/null
  systemctl restart ps5dns-xray

  if [ "$NO_FIREWALL" != 1 ]; then
    c "Firewall"
    ufw allow "$SSH_PORT"/tcp >/dev/null
    if [ -n "${IRAN_IP:-}" ]; then ufw allow from "$IRAN_IP" to any port "$TUNNEL_PORT" proto tcp >/dev/null
    else ufw allow "$TUNNEL_PORT"/tcp >/dev/null; fi
    ufw default deny incoming >/dev/null && ufw --force enable >/dev/null
  fi

  echo
  c "Foreign server ready. Copy this link; the Iran installer will ask for it:"
  echo
  cat "$DIR/tunnel-link.txt"
  echo
  echo "(Show it again later with: ps5dns link)"
  exit 0
fi

# ------------------------------------------------------------------ iran / single
# The DNS and proxy listen on ONE local IP (the one with the default route), so they never
# clash with systemd-resolved (127.0.0.53) or with sockets other software binds to other
# addresses, e.g. a VPN panel's transparent-proxy sockets on 8.8.8.8:53.
if [ -f "$DIR/.env" ] && grep -q '^LISTEN_IP=' "$DIR/.env"; then
  LISTEN_IP=$(grep '^LISTEN_IP=' "$DIR/.env" | cut -d= -f2)
fi
if [ -z "${LISTEN_IP:-}" ]; then
  LISTEN_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')
  [ -t 0 ] && read -rp "Local IP to listen on [$LISTEN_IP]: " IN && LISTEN_IP=${IN:-$LISTEN_IP}
fi
ip -4 -o addr show | grep -F "inet $LISTEN_IP/" >/dev/null || die "$LISTEN_IP is not an address of this server. Set LISTEN_IP=..."
[ "$LISTEN_IP" != "$MYIP" ] && echo "Note: this server is behind NAT ($LISTEN_IP -> $MYIP). Forward ports 53 (TCP+UDP), 80, 443 and the panel port on your router to $LISTEN_IP."

# Who holds a TCP/UDP port on LISTEN_IP (or on all addresses)? Empty = free.
port_user() {
  ss -tulnpH 2>/dev/null | awk -v p="$1" -v ip="$LISTEN_IP" \
    '$5==ip":"p || $5=="0.0.0.0:"p || $5=="*:"p || $5=="[::]:"p' \
    | { grep -o 'users:(("[^"]*' || true; } | cut -d'"' -f2 | sort -u | tr '\n' ' '
}

# Stop before changing anything if a needed port is taken.
# 53 and the panel port must be free. If 80/443 belong to another service (a website, a VPN),
# we share them: our proxy listens on hidden ports and only registered users are redirected.
SHARE_PORTS="${SHARE_PORTS:-0}"; HTTPS_PORT="${HTTPS_PORT:-4443}"; HTTP_PORT="${HTTP_PORT:-8081}"
if ! systemctl is-active --quiet ps5-smartdns; then
  P_PANEL=$( [ -f "$DIR/.env" ] && grep '^PANEL_PORT=' "$DIR/.env" | cut -d= -f2 || echo "$PANEL_PORT")
  u=$(port_user 53); [ -n "$u" ] && die "port 53 on $LISTEN_IP is used by: $u. The DNS server needs it."
  u=$(port_user "$P_PANEL"); [ -n "$u" ] && die "panel port $P_PANEL is used by: $u. Re-run with e.g. PANEL_PORT=2096"
  u80=$(port_user 80); u443=$(port_user 443)
  if [ -n "$u80$u443" ]; then
    SHARE_PORTS=1
    echo "Ports 80/443 are used by: $u80$u443-> sharing them: registered users are redirected to"
    echo "hidden ports $HTTPS_PORT/$HTTP_PORT; everyone else keeps reaching the existing service."
  fi
  if [ "$SHARE_PORTS" = 1 ]; then
    for p in "$HTTPS_PORT" "$HTTP_PORT"; do
      u=$(port_user "$p"); [ -n "$u" ] && die "port $p is used by: $u. Re-run with HTTPS_PORT=... HTTP_PORT=..."
    done
  fi
fi
TUNNEL=""
install_xray
if [ "$ROLE" = iran ]; then
  [ -n "${LINK:-}" ] || read -rp "Paste the link from the foreign server (ps5dns://...): " LINK
  TUNNEL=$(printf %s "${LINK#ps5dns://}" | base64 -d 2>/dev/null) || die "invalid link"
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); [d[k] for k in ("ip","port","uuid","pbk","sid","sni")]' "$TUNNEL" \
    || die "invalid link"
fi

# systemd-resolved stays as it is: we only bind $LISTEN_IP:53, not 127.0.0.53.

if [ ! -f "$DIR/.env" ]; then
  {
    echo "SERVER_IP=$MYIP"
    echo "LISTEN_IP=$LISTEN_IP"
    echo "SHARE_PORTS=$SHARE_PORTS"
    echo "HTTPS_PORT=$HTTPS_PORT"
    echo "HTTP_PORT=$HTTP_PORT"
    echo "PANEL_PORT=$PANEL_PORT"
    echo "ROLE=$ROLE"
    if [ -n "$TUNNEL" ]; then echo "TUNNEL='$TUNNEL'"; fi
  } > "$DIR/.env"
  chmod 600 "$DIR/.env"
fi
PANEL_PORT=$(grep '^PANEL_PORT=' "$DIR/.env" | cut -d= -f2)

cat > /etc/systemd/system/ps5-smartdns.service <<EOF
[Unit]
Description=PS5 Smart DNS (DNS + proxy + panel)
After=network-online.target
[Service]
EnvironmentFile=$DIR/.env
ExecStart=/usr/bin/python3 -u $DIR/app/app.py
Restart=always
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF

# Per-user access to 53/80/443 is enforced by the panel itself (its own nftables table
# "smartdns", which touches only those ports). ufw is never enabled or tightened here,
# so other services on this server (VPN panels, L2TP, ...) keep working.
if [ "$NO_FIREWALL" != 1 ] && ufw status 2>/dev/null | grep -q "Status: active"; then
  c "Firewall (ufw is active: opening our ports)"
  ufw allow 53 >/dev/null
  ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null
  # shared mode: redirected traffic arrives on the hidden ports
  ufw allow "$(grep '^HTTPS_PORT=' "$DIR/.env" | cut -d= -f2)"/tcp >/dev/null
  ufw allow "$(grep '^HTTP_PORT=' "$DIR/.env" | cut -d= -f2)"/tcp >/dev/null
  ufw allow "$PANEL_PORT"/tcp >/dev/null
fi

systemctl daemon-reload
systemctl enable --now ps5-smartdns >/dev/null
systemctl restart ps5-smartdns

for _ in $(seq 1 30); do [ -f "$DIR/data/initial-login.txt" ] && break; sleep 1; done
echo
c "Installed. Save these login details:"
cat "$DIR/data/initial-login.txt" 2>/dev/null || echo "Panel did not start. Check: ps5dns logs"
echo
echo "Next: open the panel, add a user, send them their link."
echo "Commands: ps5dns {login|reset-password|logs|restart|update|uninstall}"
