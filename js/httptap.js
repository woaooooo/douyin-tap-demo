// httptap.js — Android HTTP/2 API 抓包（完整版）
// 用途: frida -H 127.0.0.1:8888 -p <PID> -l js/httptap.js

// ============ 目标 SSL 库 ============
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

// ============ HPACK 静态表 (RFC 7541 附录A) ============
var ST = [null,
[":authority",""],[":method","GET"],[":method","POST"],[":path","/"],[":path","/index.html"],
[":scheme","http"],[":scheme","https"],[":status","200"],[":status","204"],[":status","206"],
[":status","304"],[":status","400"],[":status","404"],[":status","500"],
["accept-charset",""],["accept-encoding","gzip, deflate"],["accept-language",""],
["accept-ranges",""],["accept",""],["access-control-allow-origin",""],
["age",""],["allow",""],["authorization",""],["cache-control",""],
["content-disposition",""],["content-encoding",""],["content-language",""],
["content-length",""],["content-location",""],["content-range",""],["content-type",""],
["cookie",""],["date",""],["etag",""],["expect",""],["expires",""],["from",""],
["host",""],["if-match",""],["if-modified-since",""],["if-none-match",""],
["if-range",""],["if-unmodified-since",""],["last-modified",""],["link",""],
["location",""],["max-forwards",""],["proxy-authenticate",""],["proxy-authorization",""],
["range",""],["referer",""],["refresh",""],["retry-after",""],["server",""],
["set-cookie",""],["strict-transport-security",""],["transfer-encoding",""],
["user-agent",""],["vary",""],["via",""],["www-authenticate",""]
];

// ============ HPACK Huffman 码表 (RFC 7541 附录B, 0-255) ============
var HUF = [
[0x1ff8,13,0],[0x7fffd8,23,1],[0xfffffe2,28,2],[0xfffffe3,28,3],[0xfffffe4,28,4],[0xfffffe5,28,5],[0xfffffe6,28,6],[0xfffffe7,28,7],
[0xfffffe8,28,8],[0xffffea,24,9],[0x3ffffffc,30,10],[0xfffffe9,28,11],[0xfffffea,28,12],[0x3ffffffd,30,13],[0xfffffeb,28,14],[0xfffffec,28,15],
[0xfffffed,28,16],[0xfffffee,28,17],[0xfffffef,28,18],[0xffffff0,28,19],[0xffffff1,28,20],[0xffffff2,28,21],[0x3ffffffe,30,22],[0xffffff3,28,23],
[0xffffff4,28,24],[0xffffff5,28,25],[0xffffff6,28,26],[0xffffff7,28,27],[0xffffff8,28,28],[0xffffff9,28,29],[0xffffffa,28,30],[0xffffffb,28,31],
[0x14,6,32],[0x3f8,10,33],[0x3f9,10,34],[0xffa,12,35],[0x1ff9,13,36],[0x15,6,37],[0xf8,8,38],[0x7fa,11,39],
[0x3fa,10,40],[0x3fb,10,41],[0xf9,8,42],[0x7fb,11,43],[0xfa,8,44],[0x16,6,45],[0x17,6,46],[0x18,6,47],
[0x0,5,48],[0x1,5,49],[0x2,5,50],[0x19,6,51],[0x1a,6,52],[0x1b,6,53],[0x1c,6,54],[0x1d,6,55],
[0x1e,6,56],[0x1f,6,57],[0x5c,7,58],[0xfb,8,59],[0x7ffc,15,60],[0x20,6,61],[0xffb,12,62],[0x3fc,10,63],
[0x1ffa,13,64],[0x21,6,65],[0x5d,7,66],[0x5e,7,67],[0x5f,7,68],[0x60,7,69],[0x61,7,70],[0x62,7,71],
[0x63,7,72],[0x64,7,73],[0x65,7,74],[0x66,7,75],[0x67,7,76],[0x68,7,77],[0x69,7,78],[0x6a,7,79],
[0x6b,7,80],[0x6c,7,81],[0x6d,7,82],[0x6e,7,83],[0x6f,7,84],[0x70,7,85],[0x71,7,86],[0x72,7,87],
[0xfc,8,88],[0x73,7,89],[0xfd,8,90],[0x1ffb,13,91],[0x7fff0,19,92],[0x1ffc,13,93],[0x3ffc,14,94],[0x22,6,95],
[0x7ffd,15,96],[0x3,5,97],[0x23,6,98],[0x4,5,99],[0x24,6,100],[0x5,5,101],[0x25,6,102],[0x26,6,103],
[0x27,6,104],[0x6,5,105],[0x74,7,106],[0x75,7,107],[0x28,6,108],[0x29,6,109],[0x2a,6,110],[0x7,5,111],
[0x2b,6,112],[0x76,7,113],[0x2c,6,114],[0x8,5,115],[0x9,5,116],[0x2d,6,117],[0x77,7,118],[0x78,7,119],
[0x79,7,120],[0x7a,7,121],[0x7b,7,122],[0x7ffe,15,123],[0x7fc,11,124],[0x3ffd,14,125],[0x1ffd,13,126],[0xffffffc,28,127],
[0xfffe6,20,128],[0x3fffd2,22,129],[0xfffe7,20,130],[0xfffe8,20,131],[0x3fffd3,22,132],[0x3fffd4,22,133],[0x3fffd5,22,134],[0x7fffd9,23,135],
[0x3fffd6,22,136],[0x7fffda,23,137],[0x7fffdb,23,138],[0x7fffdc,23,139],[0x7fffdd,23,140],[0x7fffde,23,141],[0xffffeb,24,142],[0x7fffdf,23,143],
[0xffffec,24,144],[0xffffed,24,145],[0x3fffd7,22,146],[0x7fffe0,23,147],[0xffffee,24,148],[0x7fffe1,23,149],[0x7fffe2,23,150],[0x7fffe3,23,151],
[0x7fffe4,23,152],[0x1fffdc,21,153],[0x3fffd8,22,154],[0x7fffe5,23,155],[0x3fffd9,22,156],[0x7fffe6,23,157],[0x7fffe7,23,158],[0xffffef,24,159],
[0x3fffda,22,160],[0x1fffdd,21,161],[0xfffe9,20,162],[0x3fffdb,22,163],[0x3fffdc,22,164],[0x7fffe8,23,165],[0x7fffe9,23,166],[0x1fffde,21,167],
[0x7fffea,23,168],[0x3fffdd,22,169],[0x3fffde,22,170],[0xfffff0,24,171],[0x1fffdf,21,172],[0x3fffdf,22,173],[0x7fffeb,23,174],[0x7fffec,23,175],
[0x1fffe0,21,176],[0x1fffe1,21,177],[0x3fffe0,22,178],[0x1fffe2,21,179],[0x7fffed,23,180],[0x3fffe1,22,181],[0x7fffee,23,182],[0x7fffef,23,183],
[0xfffea,20,184],[0x3fffe2,22,185],[0x3fffe3,22,186],[0x3fffe4,22,187],[0x7ffff0,23,188],[0x3fffe5,22,189],[0x3fffe6,22,190],[0x7ffff1,23,191],
[0x3ffffe0,26,192],[0x3ffffe1,26,193],[0xfffeb,20,194],[0x7fff1,19,195],[0x3fffe7,22,196],[0x7ffff2,23,197],[0x3fffe8,22,198],[0x1ffffec,25,199],
[0x3ffffe2,26,200],[0x3ffffe3,26,201],[0x3ffffe4,26,202],[0x7ffffde,27,203],[0x7ffffdf,27,204],[0x3ffffe5,26,205],[0xfffff1,24,206],[0x1ffffed,25,207],
[0x7fff2,19,208],[0x1fffe3,21,209],[0x3ffffe6,26,210],[0x7ffffe0,27,211],[0x7ffffe1,27,212],[0x3ffffe7,26,213],[0x7ffffe2,27,214],[0xfffff2,24,215],
[0x1fffe4,21,216],[0x1fffe5,21,217],[0x3ffffe8,26,218],[0x3ffffe9,26,219],[0xffffffd,28,220],[0x7ffffe3,27,221],[0x7ffffe4,27,222],[0x7ffffe5,27,223],
[0xfffec,20,224],[0xfffff3,24,225],[0xfffed,20,226],[0x1fffe6,21,227],[0x3fffe9,22,228],[0x1fffe7,21,229],[0x1fffe8,21,230],[0x7ffff3,23,231],
[0x3fffea,22,232],[0x3fffeb,22,233],[0x1ffffee,25,234],[0x1ffffef,25,235],[0xfffff4,24,236],[0xfffff5,24,237],[0x3ffffea,26,238],[0x7ffff4,23,239],
[0x3ffffeb,26,240],[0x7ffffe6,27,241],[0x3ffffec,26,242],[0x3ffffed,26,243],[0x7ffffe7,27,244],[0x7ffffe8,27,245],[0x7ffffe9,27,246],[0x7ffffea,27,247],
[0x7ffffeb,27,248],[0xffffffe,28,249],[0x7ffffec,27,250],[0x7ffffed,27,251],[0x7ffffee,27,252],[0x7ffffef,27,253],[0x7fffff0,27,254],[0x3ffffee,26,255]
];

// 建快速查找表: "位数:code" -> 字符
var HUFMAP = {};
for (var i = 0; i < HUF.length; i++) {
    HUFMAP[HUF[i][1] + ":" + HUF[i][0]] = HUF[i][2];
}

// ============ 动态表（按 SSL 连接维护） ============
var DYNAMIC = {};
function getDyn(k) {
    if (!DYNAMIC[k]) DYNAMIC[k] = {t: [], s: 0, m: 4096};
    return DYNAMIC[k];
}
function dynAdd(d, n, v) {
    var sz = n.length + v.length + 32;
    while (d.s + sz > d.m && d.t.length) {
        var x = d.t.pop();
        d.s -= (x.n.length + x.v.length + 32);
    }
    if (sz > d.m) { d.t = []; d.s = 0; return; }
    d.t.unshift({n: n, v: v});
    d.s += sz;
}
function dynLookup(d, i) {
    if (i === 0) return null;
    if (i <= 61) {
        var e = ST[i];
        return e ? {n: e[0], v: e[1]} : null;
    }
    var p = i - 62;
    return p < d.t.length ? d.t[p] : null;
}

// ============ HPACK 整数解码 ============
function decInt(a, o, pre) {
    var m = (1 << pre) - 1;
    var v = a[o] & m;
    if (v < m) return {v: v, c: 1};
    var c = 1, sh = 0;
    while (o + c < a.length) {
        var b = a[o + c];
        v += (b & 0x7f) << sh;
        sh += 7;
        c++;
        if ((b & 0x80) === 0) break;
    }
    return {v: v, c: c};
}

// ============ HPACK Huffman 解码 ============
function huffDec(bytes) {
    var bits = "";
    for (var i = 0; i < bytes.length; i++) {
        for (var k = 7; k >= 0; k--) bits += (bytes[i] >> k) & 1;
    }
    var out = "", p = 0;
    while (p < bits.length) {
        var ok = false;
        for (var L = 5; L <= 30 && p + L <= bits.length; L++) {
            var sub = bits.substring(p, p + L);
            var key = L + ":" + parseInt(sub, 2);
            if (HUFMAP[key] !== undefined) {
                out += String.fromCharCode(HUFMAP[key]);
                p += L;
                ok = true;
                break;
            }
        }
        if (!ok) break;  // 尾部 padding 放弃
    }
    return out;
}

// ============ HPACK 字符串解码 ============
function decStr(a, o) {
    var h = (a[o] & 0x80) !== 0;
    var r = decInt(a, o, 7);
    var bytes = a.slice(o + r.c, o + r.c + r.v);
    var v;
    if (h) {
        v = huffDec(bytes);
    } else {
        v = "";
        for (var i = 0; i < bytes.length; i++) v += String.fromCharCode(bytes[i]);
    }
    return {v: v, c: r.c + r.v};
}

// ============ HPACK 主解码器 ============
function hpack(a, d) {
    var hs = [], o = 0;
    while (o < a.length) {
        var b = a[o];
        if (b & 0x80) {
            // 索引形式
            var r = decInt(a, o, 7);
            o += r.c;
            var e = dynLookup(d, r.v);
            if (e) hs.push(e.n + ": " + e.v);
        } else if (b & 0x40) {
            // 带增量索引的字面量
            var r = decInt(a, o, 6);
            o += r.c;
            var nm, vl;
            if (r.v === 0) {
                var nr = decStr(a, o); nm = nr.v; o += nr.c;
            } else {
                var e = dynLookup(d, r.v); nm = e ? e.n : ("i" + r.v);
            }
            var vr = decStr(a, o); vl = vr.v; o += vr.c;
            dynAdd(d, nm, vl);
            hs.push(nm + ": " + vl);
        } else if (b & 0x20) {
            // 动态表大小更新
            var r = decInt(a, o, 5);
            o += r.c;
            d.m = r.v;
        } else {
            // 无索引字面量
            var r = decInt(a, o, 4);
            o += r.c;
            var nm, vl;
            if (r.v === 0) {
                var nr = decStr(a, o); nm = nr.v; o += nr.c;
            } else {
                var e = dynLookup(d, r.v); nm = e ? e.n : ("i" + r.v);
            }
            var vr = decStr(a, o); vl = vr.v; o += vr.c;
            hs.push(nm + ": " + vl);
        }
    }
    return hs;
}

// ============ 关于曾经的 fix() —— 已删除 ============
// 早期版本里有个 fix()，把字母最低位翻转，声称在"还原 XOR 1 混淆"。
// 那是误判。把原始 header block 交给 Python 的 hpack 参考库解码，出来是干净的
// :status / server / content-type —— wire 上就是标准 HPACK，没有混淆。
//
// 真正的问题是 HUF 码表从符号 62 起整体错位一格（256 项错 194 项），
// 解出的字符恰好和正确字符相差 ±1，于是被误读成"混淆"。
// 码表修好后 fix() 只会把正确数据改坏，所以删掉。

// ============ 流重组 + HTTP/2 帧解析 ============
// SSL_read/SSL_write 按任意块返回，一个块可能含多个帧、也可能是半个帧。
// 必须按 (连接, 方向) 缓冲，攒够完整帧再解析。
// HPACK 动态表在请求/响应两个方向各自独立，所以 key 必须带方向。

var hooked  = {};
var PEND    = {};    // key -> 待解析字节
var HB      = {};    // key -> 未完成的 header block（CONTINUATION）
var MODE    = {};    // key -> "h2" | "h1"
var MAXLEN  = 1 << 20;
var BODYCAP = 4000;

function ckey(ssl, dir) { return ssl.toString() + ":" + dir; }

function toArray(ab) {
    var u8 = new Uint8Array(ab), a = new Array(u8.length);
    for (var i = 0; i < u8.length; i++) a[i] = u8[i];
    return a;
}

function hexline(b, n) {
    var s = "";
    for (var i = 0; i < n; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16);
    return s;
}

function feed(k, bytes) {
    var b = PEND[k];
    if (!b) b = PEND[k] = [];
    for (var i = 0; i < bytes.length; i++) b.push(bytes[i]);

    if (!MODE[k]) {
        sniff(k, b);
        if (!MODE[k]) {
            if (b.length > 65536) MODE[k] = "h2";   // 兜底，别无限缓冲
            else return;
        }
    }
    if (MODE[k] === "h1") { drainH1(k, b); return; }
    drainH2(k, b);
}

function sniff(k, b) {
    if (b.length >= 24) {
        var pre = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", ok = true;
        for (var i = 0; i < 24; i++) if (b[i] !== pre.charCodeAt(i)) { ok = false; break; }
        if (ok) { b.splice(0, 24); MODE[k] = "h2"; return; }
    }
    if (b.length >= 8) {
        var h = "";
        for (var i = 0; i < 8; i++) h += String.fromCharCode(b[i]);
        if (/^(GET|POST|PUT|DELE|HEAD|OPTI|PATC|CONN|HTTP\/)/.test(h)) {
            MODE[k] = "h1"; send({ t: "info", msg: "h1 detected " + k }); return;
        }
    }
    // preface 可能在 hook 之前就发过了，退化成按帧头合法性判断
    if (b.length >= 9) {
        var len = (b[0] << 16) | (b[1] << 8) | b[2], ty = b[3];
        if (len > 0 && len <= 16384 && ty <= 9) MODE[k] = "h2";
    }
}

function drainH2(k, b) {
    while (b.length >= 9) {
        var len = (b[0] << 16) | (b[1] << 8) | b[2];
        var ty  = b[3], fl = b[4];
        var sid = ((b[5] & 0x7f) << 24) | (b[6] << 16) | (b[7] << 8) | b[8];

        if (len > MAXLEN || ty > 9) { b.length = 0; return; }  // 帧头不可信，丢弃整块
        if (b.length < 9 + len) return;                         // 半个帧，等后续

        var pl = b.slice(9, 9 + len);
        b.splice(0, 9 + len);
        onFrame(k, ty, fl, sid, pl);
    }
}

function onFrame(k, ty, fl, sid, pl) {
    var dir = k.slice(-1);
    if (ty === 0x00) {                     // DATA
        var s = 0;
        if (fl & 0x08) s = 1 + pl[0];      // 去 padding
        if (pl.length > s) emitBody(k, sid, pl.slice(s), !!(fl & 0x01));
    } else if (ty === 0x01) {              // HEADERS
        var s = 0;
        if (fl & 0x08) s += 1 + pl[0];     // padding
        if (fl & 0x20) s += 5;             // priority
        var frag = pl.slice(s);
        if (fl & 0x04) emitHeaders(k, dir, sid, frag);
        else HB[k] = { sid: sid, frag: frag };
    } else if (ty === 0x09) {              // CONTINUATION
        var h = HB[k];
        if (!h) return;
        for (var i = 0; i < pl.length; i++) h.frag.push(pl[i]);
        if (fl & 0x04) { emitHeaders(k, dir, h.sid, h.frag); HB[k] = null; }
    }
}

function emitHeaders(k, dir, sid, frag) {
    var hs;
    try { hs = hpack(frag, getDyn(k)); }
    catch (e) { send({ t: "info", msg: "hpack err " + e }); return; }

    var raw = { path: "", auth: "", status: "", hdrs: [] };
    for (var i = 0; i < hs.length; i++) {
        var line = hs[i];
        raw.hdrs.push(line);
        if (line.indexOf(":path: ") === 0)           raw.path   = line.substring(7);
        else if (line.indexOf(":authority: ") === 0) raw.auth   = line.substring(12);
        else if (line.indexOf(":status: ") === 0)    raw.status = line.substring(9);
    }
    if (dir === "W" && !raw.path) return;
    if (dir === "R" && !raw.status) return;

    send({ t: "hdr", c: k, dir: dir, sid: sid, raw: raw });
}

function emitBody(k, sid, bytes, end) {
    if (!bytes.length) return;
    // body 是压缩的（请求 zstd / 响应 gzip），必须把原始字节整段交给 Python 解压，
    // 所以这里一律走 hex，不做可打印性判断。上限 256KB，超长的极少见。
    var lim = Math.min(bytes.length, 262144);
    send({ t: "body", c: k, dir: k.slice(-1), sid: sid,
           n: bytes.length, hex: hexline(bytes, lim), end: !!end });
}

function drainH1(k, b) {
    if (!b.length) return;
    var s = "";
    for (var i = 0; i < Math.min(b.length, 2000); i++) {
        var c = b[i];
        s += (c === 10 || c === 13 || (c >= 32 && c < 127)) ? String.fromCharCode(c) : ".";
    }
    send({ t: "raw1", dir: k.slice(-1), text: s });
    b.length = 0;
}

function hookMod(name) {
    if (hooked[name]) return;
    var m = Process.findModuleByName(name);
    if (!m) return;
    hooked[name] = true;

    var w = m.findExportByName("SSL_write");
    var r = m.findExportByName("SSL_read");

    if (w) Interceptor.attach(w, {
        onEnter: function (a) {
            try {
                var n = a[2].toInt32();
                if (n > 0 && n <= MAXLEN) feed(ckey(a[0], "W"), toArray(a[1].readByteArray(n)));
            } catch (e) {}
        }
    });

    if (r) Interceptor.attach(r, {
        onEnter: function (a) { this.buf = a[1]; this.ssl = a[0]; },
        onLeave: function (ret) {
            try {
                var n = ret.toInt32();
                if (n > 0 && n <= MAXLEN) feed(ckey(this.ssl, "R"), toArray(this.buf.readByteArray(n)));
            } catch (e) {}
        }
    });

    send({ t: "info", msg: name + " hooked (w=" + !!w + " r=" + !!r + ")" });
}

function tick() { TARGETS.forEach(hookMod); setTimeout(tick, 300); }
tick();
send({ t: "info", msg: "httptap started" });