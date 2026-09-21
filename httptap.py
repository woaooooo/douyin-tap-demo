"""
Android HTTP/2 明文抓取 —— attach 模式

复用 spawn_keylog.py 验证过的 attach 机制（spawn 会被部分 App 拦死），
hook SSL_write / SSL_read，自己做 HTTP/2 流重组 + HPACK 解码 + body 解压。

输出：
    控制台实时打印，同时写入 httptap.log

用法：
    py httptap.py --pkg <target.package.name>                # 重启目标 App 并 attach
    py httptap.py --pkg <target.package.name> --attach       # 只 attach 已运行的目标 App
    py httptap.py --pkg <target.package.name> --duration 60  # 60 秒后自动结束
"""

import frida
import os
import subprocess
import sys
import time

BASE     = os.path.dirname(os.path.abspath(__file__))
DEVICE   = "127.0.0.1:8888"
SCRIPT   = os.path.join(BASE, "js", "httptap.js")
LOG      = os.path.join(BASE, "out", "httptap.log")
SETTLE_S = 3.0
BODY_MAX = 3000     # 打印时 body 截断长度
HDR_MAX  = 400      # 单个请求头截断长度
SHOW_ALL_HEADERS = True   # True = 打印全部请求头；False = 只打印关键头

os.makedirs(os.path.dirname(LOG), exist_ok=True)


def flag_value(name, default):
    if name in sys.argv:
        i = sys.argv.index(name)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return default


ATTACH_ONLY = "--attach" in sys.argv
SETTLE_S    = float(flag_value("--wait", SETTLE_S))
DURATION    = float(flag_value("--duration", 0))
PKG         = flag_value("--pkg", None)

if not PKG:
    print("[!] 必须指定目标包名：--pkg <target.package.name>")
    sys.exit(1)


def adb(*args):
    return subprocess.run(["adb"] + list(args),
                          capture_output=True, text=True).stdout.strip()


def get_pid():
    out = adb("shell", "pidof", PKG)
    return int(out.split()[0]) if out else None


def wait_pid(timeout=20.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        pid = get_pid()
        if pid:
            return pid
        time.sleep(0.3)
    return None


log = open(LOG, "w", encoding="utf-8", errors="replace")
n_req = n_resp = n_body = 0

BODIES = {}     # (conn, dir, sid) -> bytearray，跨 DATA 帧累积


def w(line):
    print(line)
    log.write(line + "\n")
    log.flush()


def _fmt_one_header(h):
    if len(h) <= HDR_MAX:
        return h
    return h[:HDR_MAX] + "...[+%d]" % (len(h) - HDR_MAX)


def brief_all(hs):
    """输出全部请求头，一行一个。"""
    out = []
    for h in hs:
        if h.startswith(":"):
            continue
        out.append("        " + _fmt_one_header(h))
    return "\n".join(out) if out else "        (无)"


def brief_key(hs):
    """只输出关键请求头。"""
    keys = (
        "x-gorgon", "x-khronos", "x-argus", "x-tt-token",
        "bd-ticket-guard", "cookie", "user-agent",
        "x-ss-req-ticket", "x-tt-request-tag",
        "referer", "content-type", "content-length",
    )
    out = []
    for h in hs:
        if h.startswith(":"):
            continue
        low = h.lower()
        if any(low.startswith(k) for k in keys):
            out.append("        " + _fmt_one_header(h))
    return "\n".join(out) if out else "        (无关键头)"


def brief(hs):
    if SHOW_ALL_HEADERS:
        return brief_all(hs)
    return brief_key(hs)


def decompress(b):
    """抖音的 body 是压缩的：请求多为 zstd，响应多为 gzip。"""
    if b[:2] == b"\x1f\x8b":
        try:
            import gzip
            return gzip.decompress(b)
        except Exception:
            return None
    if b[:4] == b"\x28\xb5\x2f\xfd":
        try:
            import zstandard
            return zstandard.ZstdDecompressor().decompress(b, max_output_size=8 << 20)
        except Exception:
            return None
    return None


def show_body(tag, c, sid, raw, note=""):
    d = decompress(raw)
    if d is not None:
        try:
            s = d.decode("utf-8")
        except UnicodeDecodeError:
            s = repr(d[:400])
        n = len(d)
    elif all(32 <= x < 127 or x in (9, 10, 13) for x in raw[:200]):
        s, n = raw.decode("utf-8", "replace"), len(raw)
    else:
        s, n = "hex:" + raw[:80].hex(), len(raw)

    s = s.replace("\n", " ").strip()
    if len(s) > BODY_MAX:
        s = s[:BODY_MAX] + " ...[+%d]" % (len(s) - BODY_MAX)
    w("    body[%s sid=%s %dB%s%s] %s" % (tag, sid, n, "+", note, s))


def on_message(msg, data):
    global n_req, n_resp, n_body
    if msg["type"] != "send":
        if msg["type"] == "error":
            w("[ERR] " + str(msg.get("stack") or msg))
        return

    p = msg.get("payload") or {}
    if not isinstance(p, dict):
        w(str(p))
        return
    t = p.get("t")

    if t == "info":
        w("[*] " + str(p.get("msg")))

    elif t == "hdr":
        raw, d, sid = p["raw"], p["dir"], p["sid"]
        if d == "W":
            n_req += 1
            w("")
            w("### REQ  %s%s" % (raw["auth"], raw["path"]))
            w(brief(raw["hdrs"]))
        else:
            n_resp += 1
            w("--- RESP sid=%s  status=%s" % (sid, raw["status"]))
            w(brief(raw["hdrs"]))

    elif t == "body":
        n_body += 1
        key = (p["c"], p["dir"], p["sid"])
        buf = BODIES.get(key)
        if buf is None:
            buf = BODIES[key] = bytearray()
        buf += bytes.fromhex(p["hex"])
        # body 跨多个 DATA 帧时要攒齐再解压，所以等到 END_STREAM 才处理
        if p.get("end"):
            show_body("REQ " if p["dir"] == "W" else "RESP",
                      p["c"], p["sid"], bytes(buf))
            BODIES.pop(key, None)

    elif t == "raw1":
        w("[H1 %s] %s" % (p["dir"], p["text"][:400]))


def main():
    dev = frida.get_device_manager().add_remote_device(DEVICE)

    if ATTACH_ONLY:
        pid = get_pid()
        if not pid:
            print("[!] 目标 App 没在跑")
            return 1
        print("[*] pid = %d (已运行)" % pid)
    else:
        print("[*] force-stop " + PKG)
        adb("shell", "am", "force-stop", PKG)
        time.sleep(1.5)
        print("[*] launching " + PKG)
        adb("shell", "monkey", "-p", PKG, "-c",
            "android.intent.category.LAUNCHER", "1")
        pid = wait_pid()
        if not pid:
            print("[!] 等不到进程")
            return 1
        print("[*] pid = %d，等 %.1fs" % (pid, SETTLE_S))
        time.sleep(SETTLE_S)

    print("[*] attaching...")
    session = dev.attach(pid)
    session.on("detached", lambda r, *a: print("[!] detached: %s" % r))

    script = session.create_script(open(SCRIPT, encoding="utf-8").read())
    script.on("message", on_message)
    script.load()
    w("[*] httptap loaded -> " + LOG)

    try:
        if DURATION:
            t0 = time.time()
            while time.time() - t0 < DURATION:
                time.sleep(0.5)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass

    w("")
    w("[*] 收工: %d 请求 / %d 响应 / %d body 片段" % (n_req, n_resp, n_body))
    log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())