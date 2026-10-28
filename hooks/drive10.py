import sys, os, re, time, subprocess, frida, socket, tempfile

ADB = 'D:/android-sdk/platform-tools/adb.exe'
PKG = 'com.alohamobile.vpn'
PORT = 27999
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def adb(*a, t=90):
    r = subprocess.run([ADB, '-s', 'emulator-5554'] + list(a), capture_output=True, text=True, timeout=t)
    return ((r.stdout or '') + (r.stderr or '')).strip()

def port_open():
    try:
        s = socket.create_connection(('127.0.0.1', PORT), 2); s.close(); return True
    except Exception:
        return False

def ensure_server():
    for _ in range(5):
        if port_open():
            try:
                d = frida.get_device_manager().add_remote_device('127.0.0.1:%d' % PORT)
                d.enumerate_processes(); return d
            except Exception:
                pass
        adb('root', t=40); time.sleep(2)
        adb('shell', 'killall -9 fs17 fs1659 2>/dev/null'); time.sleep(1)
        adb('shell', 'setsid /data/local/tmp/fs1659 -l 127.0.0.1:%d >/dev/null 2>&1 </dev/null &' % PORT)
        adb('forward', 'tcp:%d' % PORT, 'tcp:%d' % PORT, t=20)
        for _ in range(12):
            time.sleep(1)
            if port_open(): break
    raise SystemExit('no server')

def ui_nodes():
    adb('shell', 'uiautomator dump /sdcard/_u.xml >/dev/null 2>&1')
    xml = adb('shell', 'cat /sdcard/_u.xml')
    out = []
    for m in re.finditer(r'<node[^>]*>', xml):
        s = m.group(0)
        def g(k):
            r = re.search(k + r'="([^"]*)"', s)
            return r.group(1) if r else ''
        b = g('bounds')
        mm = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', b)
        if not mm:
            continue
        x1, y1, x2, y2 = map(int, mm.groups())
        out.append({'text': g('text'), 'desc': g('content-desc'), 'cls': g('class'),
                    'click': g('clickable'), 'cx': (x1 + x2) // 2, 'cy': (y1 + y2) // 2,
                    'b': b})
    return out

def click_text(nodes, wanted):
    for n in nodes:
        t = (n['text'] or '').strip().lower()
        d = (n['desc'] or '').strip().lower()
        for w in wanted:
            if t == w or d == w or (w in t and len(t) < 40):
                adb('shell', 'input', 'tap', str(n['cx']), str(n['cy']))
                print('  click "%s" at %s' % (n['text'] or n['desc'], n['b']), flush=True)
                time.sleep(2)
                return True
    return False

dev = ensure_server()
print('[srv] ok', flush=True)
try:
    dev.enable_spawn_gating(); print('[gating] on', flush=True)
except Exception as e:
    print('[gating] fail', e)

HOOK3 = open(os.path.join(BASE, 'hooks', 'hook3.js'), encoding='utf-8').read()
HOOK5 = open(os.path.join(BASE, 'hooks', 'hook5.js'), encoding='utf-8').read()
captured = []
def mk(tag):
    def h(msg, data):
        if msg.get('type') == 'send':
            print('[%s] %s' % (tag, msg.get('payload')), flush=True)
            captured.append(msg.get('payload'))
        else:
            t = str(msg.get('stack') or msg.get('description'))
            if 'ClassNotFound' not in t:
                print('[%s-ERR] %s' % (tag, t[:200]), flush=True)
    return h

def on_spawn(sp):
    ident = sp.identifier or ''
    print('[spawn] %s %s' % (sp.pid, ident), flush=True)
    if 'alohamobile' in ident:
        try:
            sess = dev.attach(sp.pid)
            for tag, src in (('XRAY', HOOK3),):
                try:
                    sc = sess.create_script(src); sc.on('message', mk(tag)); sc.load()
                except Exception as e:
                    print('[spawn] %s fail %s' % (tag, e))
            print('[spawn] hooked %s' % sp.pid, flush=True)
        except Exception as e:
            print('[spawn] attach fail', e)
    try: dev.resume(sp.pid)
    except Exception as e: print('[spawn] resume fail', e)

dev.on('spawn-added', on_spawn)

ps = adb('shell', 'ps', '-A', '-o', 'PID,NAME')
main = [l.split()[0] for l in ps.splitlines() if 'alohamobile' in l and 'xray' not in l]
if main:
    sess = dev.attach(int(main[0]))
    sc = sess.create_script(HOOK5); sc.on('message', mk('MAIN')); sc.load()
    print('[main] hooked', main[0], flush=True)

adb('shell', 'am', 'start', '-n', PKG + '/.VpnMainActivity')
time.sleep(5)

for round_ in range(4):
    ns = ui_nodes()
    texts = [n['text'] for n in ns if n['text']]
    print('[ui] %s' % texts[:12], flush=True)
    if click_text(ns, ['ok', 'dismiss', 'got it', 'continue', 'allow', 'agree']):
        continue
    if click_text(ns, ['connect']):
        break
    if click_text(ns, ['disconnect']):
        break
    print('[ui] 未找到可点目标, 等 2s', flush=True)
    time.sleep(2)

print('[state] 已点击 connect, 观察 90s', flush=True)
t0 = time.time()
while time.time() - t0 < 90:
    time.sleep(5)

print('=== captured %d' % len(captured), flush=True)
for i, c in enumerate(captured):
    print('----- block %d -----' % i, flush=True)
    print(c, flush=True)
print('=== end')
