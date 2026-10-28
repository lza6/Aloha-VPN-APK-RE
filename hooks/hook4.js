// 抓主进程向 :xray 服务下发的配置 (Intent extras)
Java.perform(function () {
    var T = '[ALOHA-INTENT] ';
    function log(s) { console.log(T + s); }

    function dumpIntent(tag, intent) {
        if (intent === null) return;
        try {
            var s = tag + ' action=' + intent.getAction() + ' comp=' + intent.getComponent() +
                ' data=' + intent.getDataString() + ' flags=' + intent.getFlags();
            log(s);
            var ex = intent.getExtras();
            if (ex !== null) {
                var it = ex.keySet().iterator();
                while (it.hasNext()) {
                    var k = it.next();
                    var v = ex.get(k);
                    var sv = String(v);
                    if (sv.length > 6000) sv = sv.substring(0, 6000) + '...<truncated>';
                    log('   extra[' + k + '] = ' + sv);
                }
            }
        } catch (e) { log('dumpIntent err ' + e); }
    }

    try {
        var CW = Java.use('android.content.ContextWrapper');
        ['startService', 'startForegroundService', 'bindService'].forEach(function (mn) {
            try {
                CW[mn].overload('android.content.Intent').implementation = function (i) {
                    dumpIntent(mn, i);
                    return this[mn](i);
                };
                log('hooked ContextWrapper.' + mn);
            } catch (e) { log(mn + ' hook skip: ' + e); }
        });
    } catch (e) { log('CW fail ' + e); }

    // 直接盯 VpnService 派生类
    try {
        var S = Java.use('com.alohamobile.vpn.client.xray.service.AlohaXRayVpnService');
        ['onStartCommand', 'onCreate', 'onBind'].forEach(function (mn) {
            if (S[mn] === undefined) return;
            S[mn].overloads.forEach(function (ov) {
                ov.implementation = function () {
                    log('=== AlohaXRayVpnService.' + mn + ' called');
                    for (var i = 0; i < arguments.length; i++) {
                        try {
                            if (ov.argumentTypes[i].className === 'android.content.Intent') dumpIntent(mn, arguments[i]);
                        } catch (e) { }
                    }
                    return ov.apply(this, arguments);
                };
            });
        });
        log('hooked AlohaXRayVpnService');
    } catch (e) { log('xray service hook fail: ' + e); }
});
