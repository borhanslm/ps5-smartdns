"""PS5 Smart DNS - DNS (dnsmasq) + SNI proxy (Xray) + web panel with users."""
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from datetime import date, timedelta

from flask import (Blueprint, Flask, abort, flash, redirect, render_template,
                   request, session, url_for)
from jinja2 import DictLoader

DATA = os.environ.get("DATA_DIR", "/opt/ps5-smartdns/data")
GEN = os.environ.get("GEN_DIR", "/run/smartdns")
APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONF = os.path.join(DATA, "config.json")
USERS = os.path.join(DATA, "users.json")
DOMAINS = os.path.join(DATA, "domains.txt")
EXCLUDE = os.path.join(DATA, "exclude.txt")
MANAGE_SERVICES = os.environ.get("MANAGE_SERVICES", "1") == "1"

lock = threading.RLock()


# ---------------------------------------------------------------- storage
def load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()
    return f"{salt}${h}"


def check_pw(pw, stored):
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_pw(pw, salt), stored)


def read_list(path):
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                d = line.split("#", 1)[0].strip().lower().lstrip(".")
                if d:
                    out.append(d)
    except FileNotFoundError:
        pass
    return out


def write_login_file(conf, password):
    path = os.path.join(DATA, "initial-login.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"Panel URL : http://{conf['server_ip']}:{conf['panel_port']}/{conf['admin_path']}/\n"
                f"Username  : {conf['admin_user']}\nPassword  : {password}\n")
    os.chmod(path, 0o600)


def init_config():
    os.makedirs(DATA, exist_ok=True)
    conf = load(CONF, None)
    if conf is None:
        password = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(9)
        conf = {
            "server_ip": os.environ.get("SERVER_IP", "127.0.0.1"),
            "panel_port": int(os.environ.get("PANEL_PORT", "2053")),
            "admin_user": "admin",
            "pw_hash": hash_pw(password),
            "secret": secrets.token_hex(32),
            "admin_path": secrets.token_hex(5),
            "open_mode": False,
            # local IP to listen on (e.g. 192.168.100.11 behind NAT). Empty = all addresses.
            # Binding to one IP avoids clashing with other programs (VPN panels) on port 53.
            "listen_ip": os.environ.get("LISTEN_IP", ""),
            # share 80/443 with another service (website, VPN): see proxy_ports()
            "share_ports": os.environ.get("SHARE_PORTS", "0") == "1",
            "https_port": int(os.environ.get("HTTPS_PORT", "4443")),
            "http_port": int(os.environ.get("HTTP_PORT", "8081")),
            # single = this server proxies traffic itself (must be outside Iran)
            # iran   = this server tunnels traffic over VLESS Reality to a foreign server
            "role": os.environ.get("ROLE", "single"),
            "tunnel": json.loads(os.environ.get("TUNNEL") or "null"),
        }
        save(CONF, conf)
        write_login_file(conf, password)
    for name in ("domains.txt", "exclude.txt"):
        dst = os.path.join(DATA, name)
        if not os.path.exists(dst):
            with open(os.path.join(APP_DIR, "defaults", name), encoding="utf-8") as s, \
                    open(dst, "w", encoding="utf-8") as d:
                d.write(s.read())
    if not os.path.exists(USERS):
        save(USERS, [])
    return conf


# ---------------------------------------------------------------- users
def today():
    return date.today().isoformat()


def user_active(u):
    return u["enabled"] and (not u["expires"] or u["expires"] >= today())


def days_left(u):
    if not u["expires"]:
        return None
    return (date.fromisoformat(u["expires"]) - date.today()).days


def active_ips():
    ips = set()
    for u in load(USERS, []):
        if user_active(u):
            ips.update(u["ips"])
    return sorted(ips)


# ---------------------------------------------------------------- services
def proxy_ports(conf):
    """Ports our proxy listens on. Normally 443/80. In shared mode (another service such as
    a website or VPN already owns 80/443) we listen on hidden ports and only registered user
    IPs are redirected there by nftables; everyone else still reaches the original service."""
    if conf.get("share_ports"):
        return int(conf.get("https_port", 4443)), int(conf.get("http_port", 8081))
    return 443, 80


def xray_config(conf, domains):
    """Sniff the domain on 80/443. Listed domains -> tunnel (iran role) or direct (single role).
    Anything else -> the service that originally owns the port (shared mode) or dropped."""
    lip = conf.get("listen_ip") or "0.0.0.0"
    https_port, http_port = proxy_ports(conf)
    inbound = lambda tag, port, orig, sniff: {
        "tag": tag, "listen": lip, "port": port, "protocol": "dokodemo-door",
        "settings": {"network": "tcp", "address": "127.0.0.1", "port": orig},
        "sniffing": {"enabled": True, "destOverride": [sniff]}}
    tunnel = conf.get("tunnel")
    if conf.get("role") == "iran" and tunnel:
        out = {"tag": "out", "protocol": "vless",
               "settings": {"vnext": [{"address": tunnel["ip"], "port": int(tunnel["port"]),
                                       "users": [{"id": tunnel["uuid"], "encryption": "none",
                                                  "flow": "xtls-rprx-vision"}]}]},
               "streamSettings": {"network": "tcp", "security": "reality",
                                  "realitySettings": {"serverName": tunnel["sni"], "fingerprint": "chrome",
                                                      "publicKey": tunnel["pbk"], "shortId": tunnel["sid"]}}}
    else:
        out = {"tag": "out", "protocol": "freedom", "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}}
    outbounds = [out]
    rules = [{"type": "field", "inboundTag": ["in443", "in80"],
              "domain": [f"domain:{d}" for d in domains], "outboundTag": "out"}]
    if conf.get("share_ports"):
        outbounds += [
            {"tag": "orig443", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:443"}},
            {"tag": "orig80", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:80"}}]
        rules += [{"type": "field", "inboundTag": ["in443"], "outboundTag": "orig443"},
                  {"type": "field", "inboundTag": ["in80"], "outboundTag": "orig80"}]
    else:
        outbounds.append({"tag": "block", "protocol": "blackhole"})
        rules.append({"type": "field", "inboundTag": ["in443", "in80"], "outboundTag": "block"})
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [inbound("in443", https_port, 443, "tls"), inbound("in80", http_port, 80, "http")],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


class Services:
    def __init__(self):
        self.dns = None
        self.proxy = None   # xray
        self.last_fw = None

    def generate(self):
        conf = load(CONF, {})
        ip = conf["server_ip"]
        domains, exclude = read_list(DOMAINS), read_list(EXCLUDE)
        os.makedirs(GEN, exist_ok=True)
        lines = ["no-resolv", "no-hosts", "domain-needed", "bogus-priv", "filter-AAAA",
                 "cache-size=10000", "server=1.1.1.1", "server=8.8.8.8"]
        if conf.get("listen_ip"):
            lines += ["bind-interfaces", f"listen-address={conf['listen_ip']}"]
        lines += [f"address=/{d}/{ip}" for d in domains]
        lines += [f"server=/{d}/1.1.1.1" for d in exclude]
        with open(os.path.join(GEN, "dnsmasq.conf"), "w") as f:
            f.write("\n".join(lines) + "\n")
        with open(os.path.join(GEN, "xray.json"), "w") as f:
            json.dump(xray_config(conf, domains), f, indent=2)

    def firewall_script(self, conf, ips):
        # Only packets addressed to THIS server are touched. Traffic other software intercepts
        # transparently (e.g. a VPN panel's Xray proxying DNS to 8.8.8.8:53 via TPROXY) also
        # passes these hooks, but its destination is not local, so it is left alone.
        lip = conf.get("listen_ip")
        dst = f"ip daddr {lip}" if lip else "fib daddr type local"
        open_mode = conf.get("open_mode")
        https_port, http_port = proxy_ports(conf)
        s = "table inet smartdns\ndelete table inet smartdns\ntable inet smartdns {\n"
        s += "  set allowed { type ipv4_addr;%s }\n" % (
            " elements = { %s };" % ", ".join(ips) if ips else "")
        who = "" if open_mode else "ip saddr @allowed "
        if conf.get("share_ports"):
            # registered users' 80/443 -> our hidden ports; everyone else untouched
            s += "  chain prerouting {\n    type nat hook prerouting priority -110; policy accept;\n"
            s += f"    {dst} tcp dport 443 {who}redirect to :{https_port}\n"
            s += f"    {dst} tcp dport 80 {who}redirect to :{http_port}\n"
            s += "  }\n"
        s += "  chain input {\n    type filter hook input priority -10; policy accept;\n"
        s += '    iif "lo" accept\n'
        if not open_mode:
            s += f"    {dst} meta l4proto {{ tcp, udp }} th dport 53 ip saddr != @allowed drop\n"
            s += f"    {dst} tcp dport {{ {http_port}, {https_port} }} ip saddr != @allowed drop\n"
        if not lip:
            s += ("    meta nfproto ipv6 fib daddr type local meta l4proto { tcp, udp } "
                  f"th dport {{ 53, {http_port}, {https_port} }} drop\n")
        s += "  }\n}\n"
        return s

    def firewall(self, force=False):
        conf = load(CONF, {})
        ips = active_ips()
        state = (conf.get("open_mode"), tuple(ips))
        if state == self.last_fw and not force:
            return
        script = self.firewall_script(conf, ips)
        if MANAGE_SERVICES:
            r = subprocess.run(["nft", "-f", "-"], input=script, text=True, capture_output=True)
            if r.returncode != 0:
                print("nft error:", r.stderr, file=sys.stderr)
                return
        else:
            self.last_script = script
        self.last_fw = state
        print(f"firewall: {len(ips)} allowed IPs, open_mode={conf.get('open_mode')}")

    def start_dns(self):
        if self.dns and self.dns.poll() is None:
            self.dns.terminate()
            self.dns.wait(5)
        self.dns = subprocess.Popen(["dnsmasq", "-k", "--log-facility=-",
                                     "-C", os.path.join(GEN, "dnsmasq.conf")])

    def start_proxy(self):
        if self.proxy and self.proxy.poll() is None:
            self.proxy.terminate()
            try:
                self.proxy.wait(10)
            except subprocess.TimeoutExpired:
                self.proxy.kill()
        self.proxy = subprocess.Popen(["xray", "run", "-c", os.path.join(GEN, "xray.json")])

    def apply(self):
        """Regenerate configs and restart DNS + proxy."""
        with lock:
            self.generate()
            if MANAGE_SERVICES:
                t = subprocess.run(["xray", "run", "-test", "-c", os.path.join(GEN, "xray.json")],
                                   capture_output=True, text=True)
                if t.returncode != 0:
                    return t.stdout + t.stderr
                self.start_dns()
                self.start_proxy()
            self.firewall(force=True)
        return None

    def watchdog(self):
        while True:
            time.sleep(30)
            with lock:
                if MANAGE_SERVICES:
                    if self.dns is None or self.dns.poll() is not None:
                        print("dnsmasq stopped, restarting", file=sys.stderr)
                        self.start_dns()
                    if self.proxy is None or self.proxy.poll() is not None:
                        print("proxy stopped, restarting", file=sys.stderr)
                        self.start_proxy()
                self.firewall()  # drops expired users


svc = Services()

# ---------------------------------------------------------------- templates
TEMPLATES = {
"base.html": """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}PS5 Smart DNS{% endblock %}</title>
<style>
:root{--bg:#0f1218;--card:#181d26;--line:#2a313d;--text:#e6e9ef;--mute:#8b94a5;--acc:#3b82f6;--ok:#22c55e;--bad:#ef4444;--warn:#f59e0b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,Segoe UI,Tahoma,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:20px 16px}
nav{display:flex;gap:16px;align-items:center;border-bottom:1px solid var(--line);padding-bottom:12px;margin-bottom:20px;flex-wrap:wrap}
nav b{margin-right:auto}a{color:var(--acc);text-decoration:none}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
input,select,textarea{background:#0b0e13;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:8px;font:inherit}
textarea{width:100%;min-height:340px;font-family:ui-monospace,Consolas,monospace}
button{background:var(--acc);color:#fff;border:0;border-radius:6px;padding:8px 14px;font:inherit;cursor:pointer}
button.sec{background:#2a313d}button.bad{background:var(--bad)}button.sm{padding:4px 10px;font-size:13px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mute);font-weight:500;font-size:13px}.mute{color:var(--mute);font-size:13px}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px}
.on{background:#14532d;color:#bbf7d0}.off{background:#450a0a;color:#fecaca}.exp{background:#451a03;color:#fde68a}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.flash{background:#1e3a5f;padding:10px;border-radius:6px;margin-bottom:12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}.stat b{font-size:24px;display:block}
.scroll{overflow-x:auto}code{background:#0b0e13;padding:2px 6px;border-radius:4px}
</style></head><body><div class="wrap">
{% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}
{% block body %}{% endblock %}</div>
<script>function cp(t){navigator.clipboard.writeText(t);alert('Copied')}</script></body></html>""",

"login.html": """{% extends "base.html" %}{% block body %}
<div class="card" style="max-width:360px;margin:60px auto"><h2>PS5 Smart DNS</h2>
<form method="post"><p><input name="user" placeholder="Username" style="width:100%"></p>
<p><input name="pw" type="password" placeholder="Password" style="width:100%"></p>
<button style="width:100%">Login</button></form></div>{% endblock %}""",

"nav.html": """<nav><b>PS5 Smart DNS</b><a href="{{ url_for('admin.dashboard') }}">Users</a>
<a href="{{ url_for('admin.domains') }}">Domains</a><a href="{{ url_for('admin.settings') }}">Settings</a>
<a href="{{ url_for('admin.logout') }}">Logout</a></nav>""",

"dashboard.html": """{% extends "base.html" %}{% block body %}{% include "nav.html" %}
<div class="stats" style="margin-bottom:16px">
<div class="card stat"><span class="mute">DNS server IP</span><b>{{ conf.server_ip }}</b></div>
<div class="card stat"><span class="mute">Users</span><b>{{ users|length }}</b></div>
<div class="card stat"><span class="mute">Active</span><b>{{ active }}</b></div>
<div class="card stat"><span class="mute">Allowed IPs</span><b>{{ nips }}</b></div></div>
{% if conf.open_mode %}<div class="flash">Open mode is ON: anyone can use this DNS. Turn it off in Settings.</div>{% endif %}
<div class="card"><h3 style="margin-top:0">Add user</h3>
<form method="post" action="{{ url_for('admin.add_user') }}" class="row">
<input name="name" placeholder="Name" required>
<label class="mute">Days <input name="days" type="number" value="30" min="0" style="width:80px"></label>
<label class="mute">Max IPs <input name="max_ips" type="number" value="1" min="1" style="width:70px"></label>
<input name="ip" placeholder="IP (optional)">
<input name="note" placeholder="Note">
<input type="hidden" name="csrf" value="{{ csrf }}"><button>Add</button></form>
<p class="mute">Days 0 = no expiry. The user opens their link on the same internet as the console and taps "Register" to allow their IP.</p></div>
<div class="card scroll"><table><tr><th>Name</th><th>Status</th><th>IPs</th><th>Expires</th><th>Link</th><th>Actions</th></tr>
{% for u in users %}<tr>
<td>{{ u.name }}<div class="mute">{{ u.note }}</div></td>
<td>{% if not u.enabled %}<span class="pill off">disabled</span>{% elif u.dl is not none and u.dl < 0 %}<span class="pill exp">expired</span>{% else %}<span class="pill on">active</span>{% endif %}</td>
<td>{% for ip in u.ips %}<code>{{ ip }}</code><br>{% else %}<span class="mute">none</span>{% endfor %}<span class="mute">max {{ u.max_ips }}</span></td>
<td>{% if u.expires %}{{ u.expires }}<div class="mute">{{ u.dl }} days left</div>{% else %}<span class="mute">never</span>{% endif %}</td>
<td><button class="sm sec" type="button" onclick="cp('{{ base }}/u/{{ u.token }}')">Copy link</button></td>
<td><form method="post" action="{{ url_for('admin.edit_user', uid=u.id) }}" class="row">
<input type="hidden" name="csrf" value="{{ csrf }}">
<input name="days" type="number" placeholder="+days" style="width:70px"><input name="ip" placeholder="add IP" style="width:120px">
<button class="sm" name="act" value="save">Save</button>
<button class="sm sec" name="act" value="toggle">{{ 'Disable' if u.enabled else 'Enable' }}</button>
<button class="sm sec" name="act" value="clear">Clear IPs</button>
<button class="sm bad" name="act" value="delete" onclick="return confirm('Delete {{ u.name }}?')">Delete</button></form></td>
</tr>{% else %}<tr><td colspan="6" class="mute">No users yet.</td></tr>{% endfor %}</table></div>
{% endblock %}""",

"domains.html": """{% extends "base.html" %}{% block body %}{% include "nav.html" %}
<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
<div class="card"><h3 style="margin-top:0">Routed domains</h3><p class="mute">One per line, subdomains included. These go through this server.</p>
<textarea name="domains">{{ domains }}</textarea></div>
<div class="card"><h3 style="margin-top:0">Excluded subdomains</h3><p class="mute">Resolve normally (e.g. large downloads).</p>
<textarea name="exclude" style="min-height:120px">{{ exclude }}</textarea></div>
<button>Save and apply</button></form>{% endblock %}""",

"settings.html": """{% extends "base.html" %}{% block body %}{% include "nav.html" %}
<form method="post" class="card"><input type="hidden" name="csrf" value="{{ csrf }}">
<h3 style="margin-top:0">Server</h3>
<p class="mute">Mode: <b>{{ 'Iran server + VLESS tunnel' if conf.role == 'iran' else 'Single server' }}</b>
{% if conf.role == 'iran' and conf.tunnel %} &middot; tunnel to <code>{{ conf.tunnel.ip }}:{{ conf.tunnel.port }}</code> (SNI {{ conf.tunnel.sni }}){% endif %}</p>
<p><label>Server public IP (given to consoles as DNS)<br><input name="server_ip" value="{{ conf.server_ip }}"></label></p>
<p><label><input type="checkbox" name="open_mode" {% if conf.open_mode %}checked{% endif %}> Open mode: allow every IP (not recommended, attracts DNS abuse)</label></p>
<h3>Admin password</h3>
<p><input name="new_pw" type="password" placeholder="New password (leave empty to keep)"></p>
<button>Save</button></form>{% endblock %}""",

"user.html": """{% extends "base.html" %}{% block title %}My DNS{% endblock %}{% block body %}
<div class="card" style="max-width:560px;margin:20px auto">
<h2 style="margin-top:0">Hi {{ u.name }}</h2>
<p>Status: {% if not u.enabled %}<span class="pill off">disabled</span>{% elif u.dl is not none and u.dl < 0 %}<span class="pill exp">expired</span>{% else %}<span class="pill on">active</span>{% endif %}
{% if u.expires %} &middot; expires {{ u.expires }} ({{ u.dl }} days){% endif %}</p>
<p>Your current IP: <code>{{ my_ip }}</code> {% if my_ip in u.ips %}<span class="pill on">registered</span>{% endif %}</p>
{% if ipv6 %}<p class="mute">You are connected over IPv6. Turn off IPv6 or use another network to register.</p>
{% elif my_ip not in u.ips %}<form method="post"><button>Register this network</button></form>
<p class="mute">Open this page on the same internet (Wi-Fi/modem) as your console. Max {{ u.max_ips }} IP(s); the oldest is replaced.</p>{% endif %}
<h3>PS5 setup</h3><ol>
<li>Settings &rarr; Network &rarr; Settings &rarr; Set Up Internet Connection</li>
<li>Select your connection &rarr; Options &rarr; Advanced Settings</li>
<li>DNS Settings: <b>Manual</b> &mdash; Primary <code>{{ dns }}</code>, Secondary <code>{{ dns }}</code></li>
<li>OK &rarr; Test Internet Connection</li></ol>
<div dir="rtl" class="mute" style="border-top:1px solid var(--line);padding-top:10px">
این صفحه را با همان اینترنتی که کنسول به آن وصل است باز کنید و «Register this network» را بزنید.
سپس در PS5 مقدار DNS اصلی و دوم را <b>{{ dns }}</b> بگذارید. اگر IP اینترنت شما عوض شد، دوباره همین صفحه را باز کنید.</div>
</div>{% endblock %}""",
}


# ---------------------------------------------------------------- web app
def create_app():
    conf = init_config()
    app = Flask(__name__)
    app.secret_key = conf["secret"]
    app.jinja_loader = DictLoader(TEMPLATES)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      PERMANENT_SESSION_LIFETIME=timedelta(days=7))
    admin = Blueprint("admin", __name__, url_prefix="/" + conf["admin_path"])
    fails = {}

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    @admin.before_request
    def guard():
        if request.endpoint in ("admin.login",):
            return None
        if not session.get("admin"):
            return redirect(url_for("admin.login"))
        if request.method == "POST" and request.form.get("csrf") != session.get("csrf"):
            abort(400)
        return None

    def base_url():
        c = load(CONF, {})
        return f"http://{c['server_ip']}:{c['panel_port']}"

    @admin.route("/", methods=["GET"])
    def dashboard():
        users = load(USERS, [])
        for u in users:
            u["dl"] = days_left(u)
        return render_template("dashboard.html", users=users, conf=load(CONF, {}), csrf=csrf_token(),
                               active=sum(user_active(u) for u in users), nips=len(active_ips()),
                               base=base_url())

    @admin.route("/login", methods=["GET", "POST"])
    def login():
        ip = request.remote_addr
        if request.method == "POST":
            n, t = fails.get(ip, (0, 0))
            if n >= 5 and time.time() - t < 300:
                flash("Too many attempts. Wait 5 minutes.")
                return render_template("login.html")
            c = load(CONF, {})
            if request.form.get("user") == c["admin_user"] and check_pw(request.form.get("pw", ""), c["pw_hash"]):
                fails.pop(ip, None)
                session.clear()
                session.permanent = True
                session["admin"] = True
                return redirect(url_for("admin.dashboard"))
            fails[ip] = (n + 1, time.time())
            flash("Wrong username or password.")
        return render_template("login.html")

    @admin.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("admin.login"))

    def valid_ip(s):
        try:
            return isinstance(ipaddress.ip_address(s.strip()), ipaddress.IPv4Address)
        except ValueError:
            return False

    @admin.route("/users/add", methods=["POST"])
    def add_user():
        f = request.form
        days = int(f.get("days") or 0)
        ip = f.get("ip", "").strip()
        if ip and not valid_ip(ip):
            flash("Invalid IPv4 address.")
            return redirect(url_for("admin.dashboard"))
        with lock:
            users = load(USERS, [])
            users.append({
                "id": secrets.token_hex(4), "name": f["name"].strip()[:60], "note": f.get("note", "")[:120],
                "token": secrets.token_urlsafe(12), "ips": [ip] if ip else [],
                "max_ips": max(1, int(f.get("max_ips") or 1)), "enabled": True, "created": today(),
                "expires": (date.today() + timedelta(days=days)).isoformat() if days > 0 else "",
            })
            save(USERS, users)
            svc.firewall()
        flash("User added. Copy their link and send it to them.")
        return redirect(url_for("admin.dashboard"))

    @admin.route("/users/<uid>", methods=["POST"])
    def edit_user(uid):
        f = request.form
        act = f.get("act")
        with lock:
            users = load(USERS, [])
            u = next((x for x in users if x["id"] == uid), None)
            if not u:
                abort(404)
            if act == "delete":
                users.remove(u)
            elif act == "toggle":
                u["enabled"] = not u["enabled"]
            elif act == "clear":
                u["ips"] = []
            elif act == "save":
                if f.get("days"):
                    d = int(f["days"])
                    start = max(date.today(), date.fromisoformat(u["expires"])) if u["expires"] else date.today()
                    u["expires"] = (start + timedelta(days=d)).isoformat() if d > 0 else ""
                ip = f.get("ip", "").strip()
                if ip:
                    if not valid_ip(ip):
                        flash("Invalid IPv4 address.")
                    elif ip not in u["ips"]:
                        u["ips"] = (u["ips"] + [ip])[-u["max_ips"]:]
            save(USERS, users)
            svc.firewall()
        return redirect(url_for("admin.dashboard"))

    @admin.route("/domains", methods=["GET", "POST"])
    def domains():
        if request.method == "POST":
            with lock:
                for path, key in ((DOMAINS, "domains"), (EXCLUDE, "exclude")):
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(request.form.get(key, "").replace("\r", ""))
                err = svc.apply()
            flash(f"Error: {err}" if err else f"Applied {len(read_list(DOMAINS))} domains.")
            return redirect(url_for("admin.domains"))
        rd = lambda p: open(p, encoding="utf-8").read() if os.path.exists(p) else ""
        return render_template("domains.html", domains=rd(DOMAINS), exclude=rd(EXCLUDE), csrf=csrf_token())

    @admin.route("/settings", methods=["GET", "POST"])
    def settings():
        if request.method == "POST":
            with lock:
                c = load(CONF, {})
                sip = request.form.get("server_ip", "").strip()
                if not valid_ip(sip):
                    flash("Invalid server IP.")
                    return redirect(url_for("admin.settings"))
                changed = sip != c["server_ip"]
                c["server_ip"] = sip
                c["open_mode"] = bool(request.form.get("open_mode"))
                if request.form.get("new_pw"):
                    c["pw_hash"] = hash_pw(request.form["new_pw"])
                save(CONF, c)
                if changed:
                    svc.apply()
                else:
                    svc.firewall()
            flash("Settings saved.")
            return redirect(url_for("admin.settings"))
        return render_template("settings.html", conf=load(CONF, {}), csrf=csrf_token())

    app.register_blueprint(admin)

    @app.route("/u/<token>", methods=["GET", "POST"])
    def user_page(token):
        with lock:
            users = load(USERS, [])
            u = next((x for x in users if x["token"] == token), None)
            if not u:
                abort(404)
            my_ip = request.remote_addr
            ipv6 = not valid_ip(my_ip)
            if request.method == "POST" and not ipv6 and my_ip not in u["ips"]:
                if not user_active(u):
                    flash("Your account is not active. Contact the admin.")
                else:
                    u["ips"] = (u["ips"] + [my_ip])[-u["max_ips"]:]
                    save(USERS, users)
                    svc.firewall()
                    flash("Registered. You can now set the DNS on your console.")
                return redirect(url_for("user_page", token=token))
        u["dl"] = days_left(u)
        return render_template("user.html", u=u, my_ip=my_ip, ipv6=ipv6, dns=load(CONF, {})["server_ip"])

    @app.route("/")
    def index():
        return "OK", 200

    return app


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "reset-password":
        c = init_config()
        pw = secrets.token_urlsafe(9)
        c["pw_hash"] = hash_pw(pw)
        save(CONF, c)
        write_login_file(c, pw)
        print(open(os.path.join(DATA, "initial-login.txt")).read())
        return
    app = create_app()
    err = svc.apply()
    if err:
        print("proxy config error:", err, file=sys.stderr)
    threading.Thread(target=svc.watchdog, daemon=True).start()
    conf = load(CONF, {})
    print(f"Panel: http://{conf['server_ip']}:{conf['panel_port']}/{conf['admin_path']}/")
    from waitress import serve
    serve(app, host="0.0.0.0", port=conf["panel_port"], threads=8)


if __name__ == "__main__":
    main()
