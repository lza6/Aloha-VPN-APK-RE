import sys, os, time, subprocess, frida, socket

ADB = 'D:/android-sdk/platform-tools/adb.exe'
PKG = 'com.alohamobile.vpn'
PORT = 27999
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(BASE, 'memscan')
os.makedirs(OUT, exist_ok=True)

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
        adb('shell', 'setsid /data/local/tmp/fs17 -l 127.0.0.1:%d >/dev/null 2>&1 </dev/null &' % PORT)
        adb('forward', 'tcp:%d' % PORT, 'tcp:%d' % PORT, t=20)
        for _ in range(12):
            time.sleep(1)
            if port_open(): break
    raise SystemExit('no server')

AGENT = r'''
var MAXR = 512 * 1024 * 1024;
function ranges() {
    var all = Process.enumerateRanges('r--').concat(Process.enumerateRanges('rw-'));
    var seen = {}, out = [];
    for (var i = 0; i < all.length; i++) {
        var r = all[i];
        if (r.size < 4096 || r.size > MAXR) continue;
        var k = r.base.toString() + ':' + r.size;
        if (seen[k]) continue;
        seen[k] = 1;
        out.push(r);
    }
    out.sort(function (a, b) { return b.size - a.size; });
    return out;
}
rpc.exports.stat = function () {
    var rs = ranges(); var t = 0;
    for (var i = 0; i < rs.length; i++) t += rs[i].size;
    return { n: rs.length, mb: Math.round(t / 1048576) };
};
rpc.exports.grab = function (needleHex, before, after, max, budgetMB) {
    var rs = ranges();
    var budget = budgetMB * 1024 * 1024;
    var count = 0, used = 0, scanned = 0;
    for (var i = 0; i < rs.length; i++) {
        var r = rs[i];
        if (used + r.size > budget) break;
        used += r.size; scanned++;
        var m;
        try { m = Memory.scanSync(r.base, r.size, needleHex); } catch (e) { continue; }
        for (var j = 0; j < m.length; j++) {
            if (count >= max) break;
            var a = m[j].address;
            var data = null;
            if (before > 0) { try { data = Memory.readByteArray(a.sub(before), before + after); } catch (e) { data = null; } }
            if (data === null) { try { data = Memory.readByteArray(a, after); } catch (e) { data = null; } }
            if (data === null) continue;
            count++;
            send({ t: 'hit', addr: a.toString(), idx: count, len: data.byteLength }, data);
        }
        if (count >= max) break;
    }
    return { hits: count, scanned_ranges: scanned, scanned_mb: Math.round(used / 1048576) };
};
'''

def hexascii(s): return ' '.join('%02x' % b for b in s.encode())
def hexutf16(s): return ' '.join('%02x 00' % ord(c) for c in s)

pid_s = adb('shell', 'ps', '-A', '-o', 'PID,NAME')
pids = [(l.split()[0], l.split()[-1]) for l in pid_s.splitlines() if 'alohamobile' in l and 'xray' not in l]
print('main procs', pids, flush=True)
if not pids:
    raise SystemExit('app not running')
pid = int(pids[0][0])

dev = ensure_server()
print('[srv] ok', flush=True)
sess = dev.attach(pid)
sc = sess.create_script(AGENT)

TAG = ['x']; saved = []
def on_msg(msg, data):
    if msg.get('type') != 'send':
        print('[e]', msg.get('description') or msg.get('stack')); return
    p = msg.get('payload') or {}
    if p.get('t') == 'hit' and data:
        fn = os.path.join(OUT, 'b_%s_%02d_%s.bin' % (TAG[0], p['idx'], p['addr'].replace('0x', '')[:8]))
        open(fn, 'wb').write(data)
        saved.append(fn)
        print('  saved', os.path.basename(fn), len(data), flush=True)

sc.on('message', on_msg)
sc.load()
print('[stat]', sc.exports_sync.stat(), flush=True)

for tag, pat, enc in (('json', '"id":"', 'a'), ('flow', 'xtls-rprx-vision', 'a')):
    TAG[0] = tag
    hp = hexascii(pat) if enc == 'a' else hexutf16(pat)
    try:
        r = sc.exports_sync.grab(hp, 900, 4000, 3, 2000)
        print('  %-6s -> %s' % (tag, r), flush=True)
    except Exception as e:
        print('  grab err', tag, e)
    if saved:
        break

print('=== saved', len(saved))
