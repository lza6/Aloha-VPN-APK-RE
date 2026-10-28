// 抓下发给 xray 的配置: Intent.putExtra + startService + Service.onStartCommand
Java.perform(function () {
    var T = '[ALOHA-P] ';
    function log(s) { console.log(T + s); }

    try {
        var Intent = Java.use('android.content.Intent');
        ['putExtra'].forEach(function () { });
        Intent.putExtra.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
            if (v !== null && v.length > 40) log('putExtra[' + k + '] len=' + v.length + '\n' + v);
            return this.putExtra(k, v);
        };
        log('hooked Intent.putExtra(String,String)');
    } catch (e) { log('putExtra fail ' + e); }

    try {
        var CW = Java.use('android.content.ContextWrapper');
        CW.startService.overload('android.content.Intent').implementation = function (i) {
            try { log('startService comp=' + i.getComponent() + ' act=' + i.getAction()); } catch (e) { }
            return this.startService(i);
        };
        CW.startForegroundService.overload('android.content.Intent').implementation = function (i) {
            try { log('startForegroundService comp=' + i.getComponent()); } catch (e) { }
            return this.startForegroundService(i);
        };
        log('hooked ContextWrapper start(Service|ForegroundService)');
    } catch (e) { log('CW fail ' + e); }

    try {
        var S = Java.use('android.app.Service');
        if (S.onStartCommand !== undefined) {
            S.onStartCommand.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    try {
                        var i = arguments[0];
                        log('Service.onStartCommand(' + this.getClass().getName() + ') comp=' + i.getComponent());
                        var ex = i.getExtras();
                        if (ex !== null) log('   extras=' + ex.toString());
                    } catch (e) { }
                    return ov.apply(this, arguments);
                };
            });
            log('hooked Service.onStartCommand');
        }
    } catch (e) { log('Service hook fail ' + e); }
});
