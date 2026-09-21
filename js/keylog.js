/*
 * Android TLS keylog hook —— attach 模式
 *
 * 目标模块（可能有多套独立的 SSL 栈，都要挂）：
 *   默认覆盖常见命名，具体库名见 TARGETS。
 *
 * 本 build 实测（别照抄网上的脚本）：
 *   SSL_set_keylog_callback      未导出（被 strip）—— 所有网上脚本都死在这
 *   SSL_CTX_set_keylog_callback  有
 *   SSL_get_SSL_CTX              有 —— 用它把 SSL* 转 SSL_CTX*，补上被 strip 的 SSL 级 API
 *
 * 为什么必须 hook SSL_do_handshake：
 *   attach 模式下，绝大部分 SSL_CTX 在我们注入之前就已经 new 好了。
 *   只挂 SSL_CTX_new 会漏掉它们。握手前用 SSL_get_SSL_CTX 反查 CTX 再注册，才补得回来。
 */

// 默认覆盖常见命名。如果目标 App 用了别的库名，先跑一遍模块扫描：
//   Process.enumerateModules().forEach(m => {
//     const n = m.name.toLowerCase();
//     if (n.includes("ssl") || n.includes("boring") || n.includes("cronet"))
//       console.log(m.name, m.base, m.size);
//   });
//
// 抖音 / TikTok 用的是 libttboringssl.so 和 stable_cronet_libssl.so，
// 需要手动加到下面数组里。
var TARGETS = ["libssl.so", "libboringssl.so", "cronet_libssl.so"];

var seen    = Object.create(null);   // keylog 行去重
var hooked  = Object.create(null);   // 模块去重

function emit(line) {
    if (!line || seen[line]) return;
    seen[line] = true;
    // 只走 send；用 console.log 的话 frida 会再自动转发一遍，导致重复打印
    send({ type: "keylog", line: line });
}

// BoringSSL 回调签名：void (*)(const SSL *ssl, const char *line)
var cb = new NativeCallback(function (ssl, line) {
    try { emit(line.readCString()); } catch (e) {}
}, 'void', ['pointer', 'pointer']);

function hookModule(name) {
    if (hooked[name]) return;
    var m = Process.findModuleByName(name);
    if (!m) return;                  // 没加载就等下一轮
    hooked[name] = true;

    var setCtxKl = m.findExportByName("SSL_CTX_set_keylog_callback");
    var getCtx   = m.findExportByName("SSL_get_SSL_CTX");
    var ctxNew   = m.findExportByName("SSL_CTX_new");
    var hs       = m.findExportByName("SSL_do_handshake");

    if (!setCtxKl) {
        console.log("[!] " + name + ": 没有 SSL_CTX_set_keylog_callback，跳过");
        return;
    }

    var origSetCtxKl = new NativeFunction(setCtxKl, 'void', ['pointer', 'pointer']);
    var parts = [];

    // (1) 拦截 App 自己的注册调用，把回调换成我们的
    Interceptor.attach(setCtxKl, {
        onEnter: function (a) {
            try { a[1] = cb; } catch (e) {}
        }
    });
    parts.push("set_cb");

    // (2) 注入之后新建的 CTX，直接注册
    if (ctxNew) {
        Interceptor.attach(ctxNew, {
            onLeave: function (retval) {
                try { if (!retval.isNull()) origSetCtxKl(retval, cb); } catch (e) {}
            }
        });
        parts.push("CTX_new");
    }

    // (3) ★ 注入之前就已存在的 CTX —— attach 模式下的主力
    if (hs && getCtx) {
        var origGetCtx = new NativeFunction(getCtx, 'pointer', ['pointer']);
        Interceptor.attach(hs, {
            onEnter: function (a) {
                try {
                    var ctx = origGetCtx(a[0]);
                    if (!ctx.isNull()) origSetCtxKl(ctx, cb);
                } catch (e) {}
            }
        });
        parts.push("handshake->CTX");
    }

    console.log("[+] " + name + " ok: " + parts.join(", "));
    send({ type: "status", line: name + " ok: " + parts.join(", ") });
}

// cronet 是懒加载的，必须一直轮询，不能只查一次
function tick() {
    TARGETS.forEach(hookModule);
    setTimeout(tick, 300);
}
tick();
console.log("[*] keylog watcher started");