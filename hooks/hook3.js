// Aloha VPN 2.8.0 动态取证 v3 — 精简: 只挂 libXray + okhttp，不做全类枚举
Java.perform(function () {
    var T = '[ALOHA] ';
    function log(s) { console.log(T + s); }

    try {
        var LX = Java.use('libXray.LibXray');
        LX.class.getDeclaredMethods().forEach(function (m) {
            var name = m.getName();
            if (LX[name] === undefined) return;
            LX[name].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var dump = '';
                    for (var i = 0; i < arguments.length; i++) {
                        var a = arguments[i];
                        if (a === null) continue;
                        try {
                            if (ov.argumentTypes[i].className === 'java.lang.String') {
                                dump += '\n===== libXray.' + name + ' arg[' + i + '] (' + a.length + ') =====\n' + a;
                            }
                        } catch (e) { }
                    }
                    var r = ov.apply(this, arguments);
                    if (dump) log(dump);
                    return r;
                };
            });
        });
        log('libXray hooks installed');
    } catch (e) { log('libXray fail: ' + e); }

    // okhttp: 仅尝试 RealCall.execute / enqueue
    try {
        var RC = Java.use('okhttp3.internal.connection.RealCall');
        RC.execute.overload().implementation = function () {
            var req = this.request();
            log('==> ' + req.method() + ' ' + req.url().toString());
            var resp = this.execute();
            log('<== ' + resp.code() + ' ' + req.url().toString());
            return resp;
        };
        log('okhttp execute hooked');
    } catch (e) { log('okhttp fail: ' + e); }
});
