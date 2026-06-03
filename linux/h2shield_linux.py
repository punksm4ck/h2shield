#!/usr/bin/env python3
"""
================================================================================
 AEGIS H2-SHIELD (Linux)  —  HTTP/2 Bomb (CVE-2026-49975) Defense Tool
================================================================================
 PUNKS / OSIRIS-CORE  |  Kubuntu / Debian-family server-surface hardening GUI
 v1.0.1  —  fixes: scope classifier (127.x, %iface stripping), button label CSS
================================================================================
"""

import os, sys, subprocess, json, shutil, socket, re, argparse, threading, datetime
from pathlib import Path

try:
    import gi
    gi.require_version('Gtk', '3.0')
    gi.require_version('Pango', '1.0')
    from gi.repository import Gtk, GLib, Pango
    HAS_GTK = True
except Exception:
    HAS_GTK = False

VERSION = '1.0.3'
APP_DIR  = Path('/opt/h2shield')
LOG_DIR  = APP_DIR / 'logs'
REP_DIR  = APP_DIR / 'reports'
BAK_DIR  = APP_DIR / 'config_backups'

# ===========================================================================
# CORE: listening-surface audit
# ===========================================================================

def classify_scope(addr: str) -> str:
    """Classify a bind address by its actual reachability tier.
    Strips %interface suffixes before classification.
    """
    addr = addr.split('%')[0]  # strip e.g. %lo, %lxcbr0, %eth0
    if addr in ('0.0.0.0', '::', '0:0:0:0:0:0:0:0'):
        return 'All'
    if addr.startswith('127.') or addr in ('::1', '0:0:0:0:0:0:0:1'):
        return 'Loopback'
    if addr.startswith('fe80') or addr.startswith('169.254.'):
        return 'LinkLocal'
    return 'LAN'

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8337, 3210, 5000, 7000}

def classify_risk(proto: str, port: int, scope: str) -> bool:
    if proto != 'tcp':
        return False
    if scope in ('Loopback', 'LinkLocal'):
        return False
    return port in WEB_PORTS

def _run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return r.stdout, r.stderr, r.returncode

def parse_ss():
    out, err, rc = _run(['ss', '-tulpn'])
    if rc != 0:
        return [], f'ss failed: {err.strip()}'

    rows = []
    for line in out.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in ('tcp', 'udp', 'tcp6', 'udp6'):
            continue
        base_proto = 'tcp' if 'tcp' in proto else 'udp'

        local_field = parts[4]
        if local_field.startswith('['):
            m = re.match(r'\[([^\]]+)\]:(\d+)', local_field)
            if not m:
                continue
            addr, port_s = m.group(1), m.group(2)
            addr = addr.split('%')[0]
        elif local_field.count(':') > 1:
            addr = local_field.rsplit(':', 1)[0]
            port_s = local_field.rsplit(':', 1)[1]
        else:
            addr, _, port_s = local_field.rpartition(':')

        try:
            port = int(port_s)
        except ValueError:
            continue

        if addr in ('*', ''):
            addr = '0.0.0.0'

        # Strip %interface from non-bracketed addresses too (e.g. 0.0.0.0%lxcbr0)
        addr = addr.split('%')[0]

        pid, proc = None, '?'
        users_m = re.search(r'users:\(\((.+?)\)\)', line)
        if users_m:
            first = users_m.group(1).split('),(')[0]
            name_m = re.search(r'"([^"]+)"', first)
            pid_m  = re.search(r'pid=(\d+)', first)
            if name_m:
                proc = name_m.group(1)
            if pid_m:
                pid = int(pid_m.group(1))

        scope = classify_scope(addr)
        risk  = classify_risk(base_proto, port, scope)

        rows.append({
            'proto': base_proto.upper(),
            'local_addr': addr,
            'port': port,
            'pid': pid,
            'process': proc,
            'scope': scope,
            'risk': risk,
        })

    rows.sort(key=lambda r: (not r['risk'], r['port']))
    return rows, None


# ===========================================================================
# CORE: web-server detection
# ===========================================================================

def _ver_ge(v: str, minimum: str) -> bool:
    def _t(s):
        return tuple(int(x) for x in re.findall(r'\d+', s)[:3])
    try:
        return _t(v) >= _t(minimum)
    except Exception:
        return False

def detect_nginx():
    info = {'installed': False, 'version': None, 'patched_version': False,
            'config_files': [], 'http2_enabled': False, 'http2_directives': [],
            'needs_harden': False, 'error': None}
    nginx_bin = shutil.which('nginx')
    if not nginx_bin:
        for p in ('/usr/sbin/nginx', '/usr/local/sbin/nginx', '/usr/bin/nginx'):
            if os.path.exists(p):
                nginx_bin = p
                break
    if not nginx_bin:
        return info

    info['installed'] = True

    out, _, rc = _run([nginx_bin, '-v'])
    ver_m = re.search(r'nginx/(\S+)', out + _)
    if ver_m:
        info['version'] = ver_m.group(1)
        info['patched_version'] = _ver_ge(info['version'], '1.29.8')

    out, err, rc = _run([nginx_bin, '-T'])
    raw = out + err
    files_seen = set()
    for m in re.finditer(r'# configuration file (.+?):', raw):
        files_seen.add(m.group(1).strip())

    out2, err2, _ = _run([nginx_bin, '-t'])
    for m in re.finditer(r'configuration file (.+?) test', out2 + err2):
        p = m.group(1).strip()
        if os.path.exists(p):
            files_seen.add(p)

    info['config_files'] = sorted(files_seen)

    h2_found = []
    for line in raw.splitlines():
        ls = line.strip()
        if re.search(r'\bhttp2\b', ls, re.IGNORECASE) and not ls.startswith('#'):
            h2_found.append(ls)

    info['http2_directives'] = h2_found
    info['http2_enabled'] = len(h2_found) > 0
    info['needs_harden'] = info['http2_enabled'] and not info['patched_version']
    return info


def detect_apache():
    info = {'installed': False, 'version': None, 'mod_http2_version': None,
            'patched': False, 'config_files': [], 'http2_enabled': False,
            'http2_directives': [], 'needs_harden': False, 'error': None}

    apache_bin = None
    for name in ('apache2', 'httpd', 'apache2ctl'):
        b = shutil.which(name)
        if b:
            apache_bin = b
            break
    if not apache_bin:
        for p in ('/usr/sbin/apache2', '/usr/sbin/httpd'):
            if os.path.exists(p):
                apache_bin = p
                break
    if not apache_bin:
        return info

    info['installed'] = True

    out, err, _ = _run([apache_bin, '-v'])
    ver_m = re.search(r'Apache/(\S+)', out + err)
    if ver_m:
        info['version'] = ver_m.group(1)

    ctl = shutil.which('apachectl') or shutil.which('apache2ctl')
    if ctl:
        out, err, _ = _run([ctl, '-M'])
        if 'http2_module' in (out + err):
            info['http2_enabled'] = True
        try:
            pkg_out, _, rc = _run(['dpkg', '-l', 'libapache2-mod-http2'])
            if rc == 0:
                m = re.search(r'\s(\d+\.\S+)\s', pkg_out)
                if m:
                    info['mod_http2_version'] = m.group(1)
                    info['patched'] = _ver_ge(info['mod_http2_version'], '2.0.41')
        except Exception:
            pass

    conf_dirs = []
    for d in ('/etc/apache2', '/etc/httpd', '/usr/local/apache2/conf'):
        if os.path.isdir(d):
            conf_dirs.append(d)

    h2_lines = []
    conf_files_found = []
    for d in conf_dirs:
        for root, _, files in os.walk(d):
            for f in files:
                if f.endswith('.conf') or f == 'httpd.conf':
                    fp = os.path.join(root, f)
                    conf_files_found.append(fp)
                    try:
                        for line in Path(fp).read_text(errors='replace').splitlines():
                            ls = line.strip()
                            if re.search(r'\bH2\b|\bhttp2\b|Protocols\s', ls, re.IGNORECASE) and not ls.startswith('#'):
                                h2_lines.append(f'{fp}: {ls}')
                    except Exception:
                        pass

    info['config_files'] = conf_files_found
    info['http2_directives'] = h2_lines
    if not info['http2_enabled']:
        info['http2_enabled'] = any(re.search(r'\bh2\b', l, re.IGNORECASE) for l in h2_lines)
    info['needs_harden'] = info['http2_enabled'] and not info['patched']
    return info


# ===========================================================================
# CORE: hardening actions
# ===========================================================================

def _backup_file(path: str) -> str:
    BAK_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    dest = BAK_DIR / (Path(path).name + f'.{ts}.bak')
    shutil.copy2(path, dest)
    return str(dest)

def _unified_diff(original: str, modified: str, filename: str) -> str:
    import difflib
    return ''.join(difflib.unified_diff(
        original.splitlines(keepends=True),
        modified.splitlines(keepends=True),
        fromfile=f'a/{filename}',
        tofile=f'b/{filename}',
        n=3
    ))

def harden_nginx(dry_run=True):
    actions = []
    diffs = {}
    nginx_bin = shutil.which('nginx') or '/usr/sbin/nginx'
    if not os.path.exists(nginx_bin):
        return ['nginx not found — nothing to harden.'], {}

    out, err, _ = _run([nginx_bin, '-T'])
    raw = out + err

    file_set = set()
    for m in re.finditer(r'# configuration file (.+?):', raw):
        p = m.group(1).strip()
        if os.path.exists(p) and os.access(p, os.R_OK):
            file_set.add(p)

    if not file_set:
        return ['No nginx config files found in nginx -T output.'], {}

    changed_any = False
    for filepath in sorted(file_set):
        try:
            original = Path(filepath).read_text(errors='replace')
        except Exception as e:
            actions.append(f'  SKIP {filepath}: {e}')
            continue

        modified = re.sub(r'(\blisten\b[^;]*?)\s+http2\b', r'\1', original)
        modified = re.sub(r'\bhttp2\s+on\s*;', 'http2 off;', modified)

        if modified == original:
            actions.append(f'  {filepath}: no http2 directives found, skipped.')
            continue

        diff = _unified_diff(original, modified, filepath)
        diffs[filepath] = diff
        changed_any = True

        if dry_run:
            actions.append(f'  [DRY-RUN] {filepath}: would remove HTTP/2 directives (see diff).')
        else:
            bak = _backup_file(filepath)
            actions.append(f'  {filepath}: backed up to {bak}')
            try:
                Path(filepath).write_text(modified)
                actions.append(f'  {filepath}: HTTP/2 directives removed.')
            except Exception as e:
                actions.append(f'  {filepath}: WRITE FAILED — {e}  (backup at {bak})')

    if changed_any and not dry_run:
        out, err, rc = _run([nginx_bin, '-t'])
        if rc == 0:
            _, _, rc2 = _run(['nginx', '-s', 'reload'])
            if rc2 == 0:
                actions.append('nginx config test passed; reloaded.')
            else:
                actions.append('nginx -t passed but reload failed — check service.')
        else:
            actions.append(f'nginx config test FAILED after edit: {err.strip()}')
            actions.append('Review diffs and restore backups if needed.')

    return actions, diffs


def harden_apache(dry_run=True):
    actions = []
    diffs = {}

    conf_dirs = []
    for d in ('/etc/apache2', '/etc/httpd'):
        if os.path.isdir(d):
            conf_dirs.append(d)
    if not conf_dirs:
        return ['Apache config directory not found.'], {}

    for conf_dir in conf_dirs:
        for root, _, files in os.walk(conf_dir):
            for f in files:
                if not (f.endswith('.conf') or f == 'httpd.conf'):
                    continue
                filepath = os.path.join(root, f)
                try:
                    original = Path(filepath).read_text(errors='replace')
                except Exception:
                    continue

                modified = original
                modified = re.sub(
                    r'^(\s*Protocols\s+)(.*\bh2\b.*)',
                    lambda m: m.group(1) + re.sub(r'\s*\bh2c?\b', '', m.group(2)).strip(),
                    modified, flags=re.MULTILINE
                )
                modified = re.sub(r'^(\s*)(H2Engine\s+On)', r'\1H2Engine Off', modified, flags=re.MULTILINE | re.IGNORECASE)

                if modified == original:
                    continue

                diff = _unified_diff(original, modified, filepath)
                diffs[filepath] = diff

                if dry_run:
                    actions.append(f'  [DRY-RUN] {filepath}: would disable HTTP/2 (see diff).')
                else:
                    bak = _backup_file(filepath)
                    actions.append(f'  {filepath}: backed up to {bak}')
                    try:
                        Path(filepath).write_text(modified)
                        actions.append(f'  {filepath}: HTTP/2 directives removed.')
                    except Exception as e:
                        actions.append(f'  {filepath}: WRITE FAILED — {e}')

    if not dry_run and diffs:
        ctl = shutil.which('apachectl') or shutil.which('apache2ctl')
        if ctl:
            out, err, rc = _run([ctl, '-t'])
            if rc == 0:
                _run([ctl, 'graceful'])
                actions.append('Apache config test passed; graceful reload.')
            else:
                actions.append(f'Apache config test FAILED: {err.strip()}')

    return actions, diffs


def install_cgroup_limit_nginx(memory_mb=1536, dry_run=True):
    dropin_dir  = Path('/etc/systemd/system/nginx.service.d')
    dropin_file = dropin_dir / 'h2shield-memory.conf'
    content = f"""[Service]
# H2Shield: kill, don't swap, a worker that exceeds this memory limit.
MemoryMax={memory_mb}M
MemorySwapMax=0
"""
    if dry_run:
        return [f'[DRY-RUN] Would write {dropin_file}:\n{content}']
    try:
        dropin_dir.mkdir(parents=True, exist_ok=True)
        dropin_file.write_text(content)
        _run(['systemctl', 'daemon-reload'])
        _run(['systemctl', 'restart', 'nginx'])
        return [f'Wrote {dropin_file}; nginx restarted with MemoryMax={memory_mb}M.']
    except Exception as e:
        return [f'cgroup limit failed: {e}']


def install_self_heal(dry_run=True):
    service_content = f"""[Unit]
Description=AEGIS H2Shield self-heal audit
After=network.target

[Service]
Type=oneshot
ExecStart={sys.executable} {Path(__file__).resolve()} --headless --harden
StandardOutput=journal
StandardError=journal
"""
    timer_content = """[Unit]
Description=AEGIS H2Shield daily audit timer

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
"""
    svc  = Path('/etc/systemd/system/h2shield-heal.service')
    tmr  = Path('/etc/systemd/system/h2shield-heal.timer')
    if dry_run:
        return [f'[DRY-RUN] Would write {svc} and {tmr} and enable the timer.']
    try:
        svc.write_text(service_content)
        tmr.write_text(timer_content)
        _run(['systemctl', 'daemon-reload'])
        _run(['systemctl', 'enable', '--now', 'h2shield-heal.timer'])
        return [f'Installed systemd timer h2shield-heal.timer (daily 03:00, persistent).']
    except Exception as e:
        return [f'Self-heal install failed: {e}']


# ===========================================================================
# CORE: verify
# ===========================================================================

def verify_state():
    lines = []
    ts = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    lines.append(f'=== VERIFY {ts} ===')

    ng = detect_nginx()
    if ng['installed']:
        lines.append(f'nginx {ng["version"]}  patched_version: {ng["patched_version"]}')
        lines.append(f'  HTTP/2 enabled in config: {ng["http2_enabled"]}')
        for d in ng['http2_directives'][:6]:
            lines.append(f'    {d}')
        lines.append(f'  => needs_harden: {ng["needs_harden"]}')
    else:
        lines.append('nginx: not installed')

    ap = detect_apache()
    if ap['installed']:
        lines.append(f'Apache {ap["version"]}  mod_http2 {ap["mod_http2_version"]}  patched: {ap["patched"]}')
        lines.append(f'  HTTP/2 enabled: {ap["http2_enabled"]}')
        lines.append(f'  => needs_harden: {ap["needs_harden"]}')
    else:
        lines.append('Apache httpd: not installed')

    rows, _ = parse_ss()
    live_443 = [r for r in rows if r['port'] == 443 and r['scope'] in ('All', 'LAN')]
    if live_443:
        lines.append(f'Live listener on :443 ({live_443[0]["process"]}) — probing HTTP/2 negotiation...')
        curl = shutil.which('curl')
        if curl:
            out, err, _ = _run([curl, '-sI', '--http2', 'https://127.0.0.1',
                                 '--connect-timeout', '4', '-k'])
            combined = out + err
            if 'HTTP/2' in combined:
                lines.append('  curl --http2 -> still negotiating HTTP/2 (NOT hardened!)')
            elif 'HTTP/1' in combined:
                lines.append('  curl --http2 -> HTTP/1.x (correct — HTTP/2 refused)')
            else:
                lines.append(f'  curl result inconclusive: {combined[:200]}')
        else:
            lines.append('  curl not found — install curl for live negotiation test.')
    else:
        lines.append('No listener on :443 — live negotiation test skipped.')

    return lines


# ===========================================================================
# HEADLESS PATH
# ===========================================================================

def run_headless(do_harden: bool):
    for d in (LOG_DIR, REP_DIR, BAK_DIR):
        d.mkdir(parents=True, exist_ok=True)

    log_path = LOG_DIR / 'h2shield.log'
    def log(msg, level='INFO'):
        line = f'{datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")} [{level}] {msg}'
        print(line)
        with open(log_path, 'a') as f:
            f.write(line + '\n')

    rows, err = parse_ss()
    ng = detect_nginx()
    ap = detect_apache()
    drift = ng.get('needs_harden', False) or ap.get('needs_harden', False)
    log(f'Audit: {len(rows)} endpoints, drift={drift}')

    if drift:
        log('Drift detected — re-applying hardening.', 'WARN')

    if do_harden:
        if ng['installed'] and ng['needs_harden']:
            acts, _ = harden_nginx(dry_run=False)
            for a in acts:
                log(a.strip(), 'HEAL')
        if ap['installed'] and ap['needs_harden']:
            acts, _ = harden_apache(dry_run=False)
            for a in acts:
                log(a.strip(), 'HEAL')

    rep = {
        'host': socket.gethostname(),
        'timestamp': datetime.datetime.now().isoformat(),
        'version': VERSION,
        'drift': drift,
        'at_risk': [r for r in rows if r['risk']],
        'reachable': [r for r in rows if r['scope'] in ('All', 'LAN')],
        'total': len(rows),
    }
    rep_path = REP_DIR / f'audit_{rep["host"]}_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    rep_path.write_text(json.dumps(rep, indent=2))
    log(f'Report -> {rep_path}')


# ===========================================================================
# GTK GUI
# ===========================================================================

DARK_BG    = '#0d1117'
PANEL_BG   = '#161b22'
ACCENT     = '#58a6ff'
GREEN      = '#238636'
RED_WARN   = '#da3633'
FG_MAIN    = '#c9d1d9'
FG_DIM     = '#8b949e'
FG_GREEN   = '#7ee787'
BTN_DARK   = '#21262d'
BTN_BLUE   = '#1f6feb'

# FIX: use !important on button label colors so KDE/Breeze theme can't override them.
# Also add explicit label { color } inside button rules since GTK3 themes often
# target the GtkLabel child rather than the button widget itself.
CSS = f"""
window {{ background-color: {DARK_BG}; color: {FG_MAIN}; }}
.header {{ font-size: 22px; font-weight: bold; color: {ACCENT}; }}
.sub {{ color: {FG_DIM}; font-size: 12px; }}
.panel {{ background-color: {PANEL_BG}; border-radius: 4px; padding: 8px; }}
.mono {{ font-family: monospace; font-size: 12px; }}
.log  {{ font-family: monospace; font-size: 12px; color: {FG_GREEN}; }}
.status {{ color: {FG_DIM}; font-size: 11px; }}
.btn-dark  {{ background-color: {BTN_DARK}; color: {FG_MAIN}; border: 1px solid #30363d; }}
.btn-dark label  {{ color: {FG_MAIN}; }}
.btn-green {{ background-color: {GREEN};    color: #ffffff; border: none; }}
.btn-green label {{ color: #ffffff; }}
.btn-blue  {{ background-color: {BTN_BLUE}; color: #ffffff; border: none; }}
.btn-blue label  {{ color: #ffffff; }}
.btn-red   {{ background-color: {RED_WARN}; color: #ffffff; border: none; }}
.btn-red label   {{ color: #ffffff; }}
progressbar trough   {{ background-color: {DARK_BG}; }}
progressbar progress {{ background-color: {GREEN}; }}
treeview {{ background-color: {DARK_BG}; color: {FG_MAIN}; font-family: monospace; font-size: 12px; }}
treeview:selected {{ background-color: #1f6feb; }}
"""

def _load_css():
    prov = Gtk.CssProvider()
    prov.load_from_data(CSS.encode())
    try:
        from gi.repository import Gdk
        screen = Gdk.Screen.get_default()
        if screen is not None:
            Gtk.StyleContext.add_provider_for_screen(
                screen, prov, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
    except Exception:
        pass

AUDIT_STAGES = [
    ('Enumerating listening ports', 20),
    ('Detecting nginx state',       45),
    ('Detecting Apache state',      65),
    ('Analysing surface',           80),
    ('Writing report',             100),
]
HARDEN_STAGES = [
    ('Enumerating listening ports', 10),
    ('Detecting nginx / Apache',    25),
    ('Hardening nginx config',      55),
    ('Hardening Apache config',     75),
    ('Applying cgroup memory cap',  90),
    ('Writing report',             100),
]

class H2ShieldWindow(Gtk.Window):

    def __init__(self):
        super().__init__(title=f'AEGIS H2-SHIELD v{VERSION} — CVE-2026-49975 Defense (Linux)')
        self.set_default_size(1100, 700)
        self.connect('destroy', Gtk.main_quit)

        _load_css()
        for d in (LOG_DIR, REP_DIR, BAK_DIR):
            d.mkdir(parents=True, exist_ok=True)

        self._state = {
            'running': False,
            'stage': 'Idle.',
            'pct': 0,
            'metric': '',
            'start': None,
            'result': None,
            'error': None,
        }

        self._build_ui()
        self.show_all()
        GLib.idle_add(self._start_audit, False)

    def _build_ui(self):
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        outer.set_margin_top(12); outer.set_margin_bottom(12)
        outer.set_margin_start(12); outer.set_margin_end(12)
        self.add(outer)

        hdr = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        title = Gtk.Label(label='AEGIS H2-SHIELD')
        title.get_style_context().add_class('header')
        sub = Gtk.Label(label='HTTP/2 Bomb (CVE-2026-49975) server-surface auditor + hardener — Linux')
        sub.get_style_context().add_class('sub')
        hdr.pack_start(title, False, False, 0)
        hdr.pack_start(sub, False, False, 8)
        outer.pack_start(hdr, False, False, 0)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn_box.set_margin_top(12); btn_box.set_margin_bottom(8)
        self._btn_audit   = self._btn('Run Audit',         'btn-dark',  self._on_audit)
        self._btn_harden  = self._btn('Audit + Harden',    'btn-green', self._on_harden)
        self._btn_verify  = self._btn('Verify',            'btn-blue',  self._on_verify)
        self._btn_heal    = self._btn('Install Self-Heal', 'btn-dark',  self._on_install_heal)
        self._btn_reports = self._btn('Open Reports',      'btn-dark',  self._on_reports)
        for b in (self._btn_audit, self._btn_harden, self._btn_verify, self._btn_heal, self._btn_reports):
            b.set_size_request(140, 34)
            btn_box.pack_start(b, False, False, 0)
        outer.pack_start(btn_box, False, False, 0)

        prog_frame = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        prog_frame.get_style_context().add_class('panel')
        prog_frame.set_margin_bottom(8)

        metric_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self._stage_lbl  = Gtk.Label(label='Idle.')
        self._stage_lbl.set_halign(Gtk.Align.START)
        self._metric_lbl = Gtk.Label(label='')
        self._metric_lbl.set_halign(Gtk.Align.END)
        for l in (self._stage_lbl, self._metric_lbl):
            l.get_style_context().add_class('mono')
        metric_row.pack_start(self._stage_lbl,  True,  True,  0)
        metric_row.pack_start(self._metric_lbl, False, False, 0)
        prog_frame.pack_start(metric_row, False, False, 0)

        self._bar = Gtk.ProgressBar()
        self._bar.set_fraction(0.0)
        prog_frame.pack_start(self._bar, False, False, 0)
        outer.pack_start(prog_frame, False, False, 0)

        nb = Gtk.Notebook()
        nb.set_vexpand(True)
        outer.pack_start(nb, True, True, 0)

        surf_scroll = Gtk.ScrolledWindow()
        surf_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self._surface_store = Gtk.ListStore(str, str, str, str, str, str, str)
        self._surface_tv    = Gtk.TreeView(model=self._surface_store)
        for i, col in enumerate(['Proto', 'Address', 'Port', 'Process', 'PID', 'Scope', 'Risk']):
            cr = Gtk.CellRendererText()
            tc = Gtk.TreeViewColumn(col, cr, text=i)
            tc.set_resizable(True)
            self._surface_tv.append_column(tc)
        surf_scroll.add(self._surface_tv)
        nb.append_page(surf_scroll, Gtk.Label(label='Listening Surface'))

        srv_scroll = Gtk.ScrolledWindow()
        srv_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self._srv_text = self._mono_textview()
        srv_scroll.add(self._srv_text)
        nb.append_page(srv_scroll, Gtk.Label(label='nginx / Apache'))

        log_scroll = Gtk.ScrolledWindow()
        log_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self._log_text = self._mono_textview(css_class='log')
        log_scroll.add(self._log_text)
        nb.append_page(log_scroll, Gtk.Label(label='Actions / Log'))

        diff_scroll = Gtk.ScrolledWindow()
        diff_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self._diff_text = self._mono_textview()
        diff_scroll.add(self._diff_text)
        nb.append_page(diff_scroll, Gtk.Label(label='Config Diffs'))

        self._status_lbl = Gtk.Label(label='Ready.')
        self._status_lbl.set_halign(Gtk.Align.START)
        self._status_lbl.get_style_context().add_class('status')
        self._status_lbl.set_margin_top(6)
        outer.pack_start(self._status_lbl, False, False, 0)

        GLib.timeout_add(100, self._tick)

    def _btn(self, label, css_class, handler):
        b = Gtk.Button(label=label)
        b.get_style_context().add_class(css_class)
        b.connect("clicked", handler)
        lbl = b.get_child()
        if lbl:
            from gi.repository import Pango
            c = {"btn-green":"ffffff","btn-blue":"ffffff","btn-red":"ffffff","btn-dark":"c9d1d9"}.get(css_class,"c9d1d9")
            a = Pango.AttrList()
            a.insert(Pango.attr_foreground_new(int(c[0:2],16)*257,int(c[2:4],16)*257,int(c[4:6],16)*257))
            lbl.set_attributes(a)
        return b

    def _mono_textview(self, css_class='mono'):
        tv = Gtk.TextView()
        tv.set_editable(False)
        tv.set_cursor_visible(False)
        tv.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        tv.get_style_context().add_class(css_class)
        return tv

    def _start_audit(self, do_harden: bool):
        if self._state['running']:
            return
        self._state.update({'running': True, 'stage': 'Starting…', 'pct': 0,
                             'metric': '', 'start': datetime.datetime.now(),
                             'result': None, 'error': None})
        for b in (self._btn_audit, self._btn_harden, self._btn_verify, self._btn_heal):
            b.set_sensitive(False)

        stages = HARDEN_STAGES if do_harden else AUDIT_STAGES

        def worker():
            try:
                result = {'rows': [], 'ng': {}, 'ap': {}, 'actions': [], 'diffs': {}}

                def advance(i):
                    name, pct = stages[i]
                    self._state['stage'] = name
                    self._state['pct']   = pct

                advance(0)
                rows, err = parse_ss()
                result['rows'] = rows
                self._state['metric'] = f'endpoints: {len(rows)}'

                advance(1)
                ng = detect_nginx()
                result['ng'] = ng
                self._state['metric'] = f'endpoints: {len(rows)} | nginx: {ng["installed"]}'

                advance(2)
                ap = detect_apache()
                result['ap'] = ap
                self._state['metric'] = (f'endpoints: {len(rows)} | '
                    f'nginx: {ng["installed"]} | apache: {ap["installed"]}')

                if do_harden:
                    advance(3)
                    all_actions = []
                    all_diffs   = {}
                    if ng['installed'] and ng['needs_harden']:
                        acts, diffs = harden_nginx(dry_run=False)
                        all_actions += acts
                        all_diffs.update(diffs)
                    elif ng['installed']:
                        all_actions.append('nginx: already mitigated or not at risk — no changes.')

                    advance(4)
                    if ap['installed'] and ap['needs_harden']:
                        acts, diffs = harden_apache(dry_run=False)
                        all_actions += acts
                        all_diffs.update(diffs)
                    elif ap['installed']:
                        all_actions.append('Apache: already mitigated or not at risk — no changes.')

                    cg = install_cgroup_limit_nginx(dry_run=False)
                    all_actions += cg
                    result['actions'] = all_actions
                    result['diffs']   = all_diffs
                else:
                    advance(3)
                    dry_acts = []
                    dry_diffs = {}
                    if ng['installed']:
                        acts, diffs = harden_nginx(dry_run=True)
                        dry_acts += acts
                        dry_diffs.update(diffs)
                    if ap['installed']:
                        acts, diffs = harden_apache(dry_run=True)
                        dry_acts += acts
                        dry_diffs.update(diffs)
                    result['actions'] = dry_acts
                    result['diffs']   = dry_diffs

                advance(len(stages) - 1)
                REP_DIR.mkdir(parents=True, exist_ok=True)
                rep = {
                    'host': socket.gethostname(),
                    'timestamp': datetime.datetime.now().isoformat(),
                    'version': VERSION,
                    'hardened': do_harden,
                    'nginx': {k: v for k, v in ng.items() if k != 'config_files'},
                    'apache': {k: v for k, v in ap.items() if k not in ('config_files', 'http2_directives')},
                    'at_risk': [r for r in rows if r['risk']],
                    'reachable_count': len([r for r in rows if r['scope'] in ('All', 'LAN')]),
                    'total': len(rows),
                }
                rep_name = REP_DIR / f'audit_{rep["host"]}_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
                rep_name.write_text(json.dumps(rep, indent=2))
                result['report'] = rep
                self._state['result'] = result

            except Exception as e:
                import traceback
                self._state['error'] = f'{e}\n{traceback.format_exc()}'
            finally:
                self._state['running'] = False
                self._state['stage']   = 'Complete.'
                self._state['pct']     = 100

        threading.Thread(target=worker, daemon=True).start()

    def _tick(self):
        s = self._state
        self._stage_lbl.set_text(s['stage'])
        self._bar.set_fraction(s['pct'] / 100.0)

        if s['start']:
            elapsed = (datetime.datetime.now() - s['start']).total_seconds()
            eta_str = ''
            if 3 < s['pct'] < 100:
                total = elapsed * (100 / s['pct'])
                rem = max(0, round(total - elapsed))
                eta_str = f'  ETA ~{rem}s'
            self._metric_lbl.set_text(
                str(s['metric']) + f'  |  elapsed {round(elapsed,1)}s' + eta_str
            )

        if not s['running'] and (s['result'] or s['error']):
            if s['error']:
                self._append_log(f'ERROR: {s["error"]}\n')
                self._status_lbl.set_text('Audit failed — see Actions/Log tab.')
            elif s['result']:
                self._apply_result(s['result'])
            for b in (self._btn_audit, self._btn_harden, self._btn_verify, self._btn_heal):
                b.set_sensitive(True)
            s['result'] = None
            s['error']  = None

        return True

    def _apply_result(self, result):
        rows    = result.get('rows', [])
        ng      = result.get('ng', {})
        ap      = result.get('ap', {})
        actions = result.get('actions', [])
        diffs   = result.get('diffs', {})

        self._surface_store.clear()
        for r in rows:
            self._surface_store.append([
                r['proto'], r['local_addr'], str(r['port']),
                r['process'], str(r['pid'] or '?'),
                r['scope'], '⚠ YES' if r['risk'] else 'no'
            ])

        srv_lines = []
        if ng.get('installed'):
            srv_lines += [
                f'nginx {ng.get("version","?")}',
                f'  patched_version (>=1.29.8): {ng.get("patched_version")}',
                f'  http2 in config: {ng.get("http2_enabled")}',
                f'  needs_harden: {ng.get("needs_harden")}',
                f'  directives found:',
            ] + [f'    {d}' for d in ng.get('http2_directives', [])[:10]]
        else:
            srv_lines.append('nginx: not installed')

        srv_lines.append('')
        if ap.get('installed'):
            srv_lines += [
                f'Apache {ap.get("version","?")}  mod_http2: {ap.get("mod_http2_version","?")}',
                f'  patched (mod_http2 >= 2.0.41): {ap.get("patched")}',
                f'  http2 in config: {ap.get("http2_enabled")}',
                f'  needs_harden: {ap.get("needs_harden")}',
            ]
        else:
            srv_lines.append('Apache httpd: not installed')

        self._srv_text.get_buffer().set_text('\n'.join(srv_lines))

        ts = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        at_risk   = len([r for r in rows if r['risk']])
        reachable = len([r for r in rows if r['scope'] in ('All', 'LAN')])
        self._append_log(f'=== {socket.gethostname()}  {ts} ===\n')
        for a in actions:
            self._append_log(f'  {a}\n')

        if diffs:
            diff_txt = '\n\n'.join(f'--- {fp} ---\n{d}' for fp, d in diffs.items())
            self._diff_text.get_buffer().set_text(diff_txt)
        else:
            self._diff_text.get_buffer().set_text('(no config diffs — nothing changed or no servers found)')

        ng_state = ('hardened' if ng.get('installed') and not ng.get('needs_harden')
                    else ('⚠ needs harden' if ng.get('needs_harden') else 'absent'))
        ap_state = ('hardened' if ap.get('installed') and not ap.get('needs_harden')
                    else ('⚠ needs harden' if ap.get('needs_harden') else 'absent'))
        self._status_lbl.set_text(
            f'Total: {len(rows)}  Reachable: {reachable}  At-risk: {at_risk}  '
            f'nginx: {ng_state}  Apache: {ap_state}'
        )

    def _append_log(self, text: str):
        buf = self._log_text.get_buffer()
        it = buf.get_end_iter()
        buf.insert(it, text)

    def _on_audit(self, _btn):
        self._start_audit(False)

    def _on_harden(self, _btn):
        dialog = Gtk.MessageDialog(
            transient_for=self,
            modal=True,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.YES_NO,
            text='Apply hardening?'
        )
        dialog.format_secondary_text(
            'This will:\n'
            '  • Back up each nginx/Apache config file before touching it\n'
            '  • Remove HTTP/2 directives from configs\n'
            '  • Reload the web server\n'
            '  • Set a cgroup memory cap on nginx workers\n\n'
            'Config files are backed up to /opt/h2shield/config_backups/\n'
            'Review the Config Diffs tab after the run.\n\n'
            'Only servers with HTTP/2 ENABLED and NO upstream patch will be modified.'
        )
        resp = dialog.run()
        dialog.destroy()
        if resp == Gtk.ResponseType.YES:
            self._start_audit(True)

    def _on_verify(self, _btn):
        lines = verify_state()
        ts = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        self._append_log(f'\n=== VERIFY {ts} ===\n')
        for l in lines:
            self._append_log(f'  {l}\n')

    def _on_install_heal(self, _btn):
        dialog = Gtk.MessageDialog(
            transient_for=self,
            modal=True,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text='Install systemd self-heal timer?'
        )
        dialog.format_secondary_text(
            'Installs h2shield-heal.service + h2shield-heal.timer\n'
            'Runs daily at 03:00, re-applies hardening if drift is detected.\n'
            'Requires systemd and sudo/root.'
        )
        resp = dialog.run()
        dialog.destroy()
        if resp == Gtk.ResponseType.YES:
            acts = install_self_heal(dry_run=False)
            ts   = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
            self._append_log(f'\n=== SELF-HEAL INSTALL {ts} ===\n')
            for a in acts:
                self._append_log(f'  {a}\n')

    def _on_reports(self, _btn):
        REP_DIR.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(['xdg-open', str(REP_DIR)])


# ===========================================================================
# ENTRY POINT
# ===========================================================================

def main():
    ap = argparse.ArgumentParser(description='AEGIS H2-SHIELD — CVE-2026-49975 defense tool (Linux)')
    ap.add_argument('--headless', action='store_true', help='Run audit without GUI (for cron/systemd)')
    ap.add_argument('--harden',   action='store_true', help='Apply hardening (default: audit-only)')
    ap.add_argument('--update-url', default='', help='URL to fetch a newer version of this script')
    args = ap.parse_args()

    if os.geteuid() != 0:
        print('WARNING: not running as root — some detections and all hardening actions require sudo.')

    if args.headless:
        run_headless(args.harden)
        return

    if not HAS_GTK:
        print('ERROR: GTK3 Python bindings not found.\n'
              'Install with:  sudo apt install python3-gi gir1.2-gtk-3.0 gir1.2-pango-1.0\n'
              'Then re-run this script.')
        sys.exit(1)

    win = H2ShieldWindow()
    Gtk.main()


if __name__ == '__main__':
    main()
