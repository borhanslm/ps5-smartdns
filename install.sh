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
  iran)    apt-get install -y -qq $BASE dnsmasq-base python3 python3-flask python3-waitress ;;
  single)  apt-get install -y -qq $BASE dnsmasq-base python3 python3-flask python3-waitress nginx libnginx-mod-stream
           systemctl disable --now nginx >/dev/null 2>&1 || true ;;
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
  "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}}]
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
TUNNEL=""
if [ "$ROLE" = iran ]; then
  install_xray
  [ -n "${LINK:-}" ] || read -rp "Paste the link from the foreign server (ps5dns://...): " LINK
  TUNNEL=$(printf %s "${LINK#ps5dns://}" | base64 -d 2>/dev/null) || die "invalid link"
  python3 -c 'import json,sys; d=json.loads(sys.argv[1]); [d[k] for k in ("ip","port","uuid","pbk","sid","sni")]' "$TUNNEL" \
    || die "invalid link"
fi

# free port 53 (Ubuntu's systemd-resolved stub listener)
if systemctl is-active --quiet systemd-resolved; then
  mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNSStubListener=no\nDNS=1.1.1.1 8.8.8.8\n' > /etc/systemd/resolved.conf.d/ps5dns.conf
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  systemctl restart systemd-resolved
fi

if [ ! -f "$DIR/.env" ]; then
  {
    echo "SERVER_IP=$MYIP"
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

c "Firewall"
ufw allow "$SSH_PORT"/tcp >/dev/null
ufw allow 53 >/dev/null
ufw allow 80/tcp >/dev/null
ufw allow 443/tcp >/dev/null
ufw allow "$PANEL_PORT"/tcp >/dev/null
ufw default deny incoming >/dev/null && ufw --force enable >/dev/null
# Per-user access to 53/80/443 is enforced by the panel (nftables table "smartdns").

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
