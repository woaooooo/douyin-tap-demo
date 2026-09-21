"""
Android TLS 抓包 + keylog 采集 —— attach 模式，一键完成

（文件名保留 spawn_keylog 是为了不改你的习惯，但它已经不用 spawn 了。）

为什么不用 spawn：
    实测 frida 17.17.0 spawn 抖音会卡在启动阶段
    -> frida.TimedOutError: unexpectedly timed out while waiting for app to launch
    同一个 frida spawn com.android.settings 完全正常，所以是抖音专门拦 spawn。
    改成：自己启动 App，等它跑起来，再 attach。实测 attach 成功且 App 不崩。

为什么不用 dev.enumerate_processes() 找 PID：
    抖音把进程名 PR_SET_NAME 成了 GBK 编码的「抖音」，
    frida 按 UTF-8 解出来是乱码 '????'，匹配包名和中文名都匹配不上。
    改用 adb shell pidof，它读的是 cmdline，拿得到真实包名。

抓包时序（很重要）：
    tcpdump 在 attach 成功之后才启动。这保证 pcap 里出现的每条 TLS 连接，
    keylog 里都有对应密钥 —— 不会出现"有密文没密钥"解不开的情况。
    代价是 App 启动最初那几秒的流量不抓（那些流量本来也拿不到密钥）。

用法：
    py spawn_keylog.py --pkg <target.package.name>                # 重启目标 App + attach + 抓包
    py spawn_keylog.py --pkg <target.package.name> --attach       # 只 attach 当前已运行的
    py spawn_keylog.py --pkg <target.package.name> --no-pcap      # 只要 keylog，不抓包
    py spawn_keylog.py --pkg <target.package.name> --wait 1.5     # 缩短 attach 前等待
    py spawn_keylog.py --pkg <target.package.name> --duration 90  # 抓 90 秒自动收工
    py spawn_keylog.py --pkg <target.package.name> --iface wlan0  # 不用 -i any（见下）

    Ctrl+C 停止：会自动结束 tcpdump 并把 pcap 拉回本地。

关于 -i any 和 linktype：
    默认 -i any 会产出 LINUX_SLL2 帧（pcap 头 linktype=276）。
    Wireshark 4.0+ 能认；老版本可能报 unknown link type。
    真遇到就加 --iface wlan0，生成普通以太网帧（linktype=1）。

已知覆盖缺口：
    pcap 里部分 ClientHello 对不上密钥，大概来自静态链接 boringssl 的库，
    符号没导出，挂不上。要补这部分换 r0capture 从更上层拿明文更划算。
"""

import frida
import os
import subprocess
import sys
import time

BASE      = os.path.dirname(os.path.abspath(__file__))
DEVICE    = "127.0.0.1:8888"
SCRIPT    = os.path.join(BASE, "js", "keylog.js")
OUT       = os.path.join(BASE, "out", "sslkeylog.txt")
PCAP_DEV  = "/data/local/tmp/target.pcap"
PCAP_OUT  = os.path.join(BASE, "out", "target.pcap")

os.makedirs(os.path.dirname(OUT), exist_ok=True)

SETTLE_S  = 3.0          # 启动后等多久再 attach。太早可能踩到早期反调试检查
IFACE     = "any"
BPF       = "port 443"


def flag_value(name, default):
    if name in sys.argv:
        i = sys.argv.index(name)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return default


ATTACH_ONLY = "--attach" in sys.argv
NO_PCAP     = "--no-pcap" in sys.argv
SETTLE_S    = float(flag_value("--wait", SETTLE_S))
DURATION    = float(flag_value("--duration", 0))   # 0 = 一直跑到 Ctrl+C
IFACE       = flag_value("--iface", IFACE)
PKG         = flag_value("--pkg", None)

if not PKG:
    print("[!] 必须指定目标包名：--pkg <target.package.name>")
    sys.exit(1)


def adb(*args):
    r = subprocess.run(["adb"] + list(args), capture_output=True, text=True)
    return r.stdout.strip()


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


def start_tcpdump():
    # 清残留：上次异常退出留下的 tcpdump 会和这次抢同一个输出文件，必须先干掉。
    adb("shell", "su", "-c", "pkill -INT tcpdump; sleep 1; pkill -9 tcpdump")
    adb("shell", "su", "-c", "rm -f " + PCAP_DEV)
    p = subprocess.Popen(
        ["adb", "shell", "su", "-c",
         "/system/bin/tcpdump -i %s -w %s -s 0 '%s'" % (IFACE, PCAP_DEV, BPF)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)
    return p


def stop_tcpdump(proc):
    # SIGINT 让 tcpdump 正常收尾、把缓冲刷盘，再 pull 才是完整的
    adb("shell", "su", "-c", "pkill -INT tcpdump")
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    time.sleep(1.0)
    size = adb("shell", "su", "-c", "stat -c %s " + PCAP_DEV)
    adb("pull", PCAP_DEV, PCAP_OUT)
    return size


n_keys = 0


def on_message(msg, data):
    global n_keys
    if msg["type"] == "send":
        p = msg.get("payload") or {}
        kind = p.get("type")
        if kind == "keylog":
            n_keys += 1
            with open(OUT, "a", encoding="utf-8") as f:
                f.write(p["line"] + "\n")
            print("[KEY %3d] %s" % (n_keys, p["line"][:70]))
        elif kind == "status":
            print("[HOOK] " + p["line"])
    elif msg["type"] == "error":
        print("[ERR] " + str(msg.get("stack") or msg))


def main():
    open(OUT, "w").close()
    dev = frida.get_device_manager().add_remote_device(DEVICE)

    if ATTACH_ONLY:
        pid = get_pid()
        if not pid:
            print("[!] 目标 App 没在跑，先去掉 --attach")
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
            print("[!] 20s 内没等到进程，放弃")
            return 1
        print("[*] pid = %d，等 %.1fs 再 attach" % (pid, SETTLE_S))
        time.sleep(SETTLE_S)

    print("[*] attaching...")
    session = dev.attach(pid)

    def on_detach(reason, *a):
        print("[!] session 断开: %s （App 可能被杀了）" % reason)
    session.on("detached", on_detach)

    script = session.create_script(open(SCRIPT, encoding="utf-8").read())
    script.on("message", on_message)
    script.load()
    print("[*] script loaded，密钥实时写入 " + OUT)

    td = None
    if not NO_PCAP:
        print("[*] 启动 tcpdump (BPF: %s)..." % BPF)
        td = start_tcpdump()
        print("[*] 抓包中 -> " + PCAP_DEV)

    print("[*] >>> 现在去操作目标 App <<<   %s"
          % ("Ctrl+C 结束" if not DURATION else "%.0fs 后自动结束" % DURATION))

    # finally 兜底：中途抛异常也要把 tcpdump 收掉，
    # 否则设备上会留下僵尸 tcpdump，下次跑就和它抢同一个输出文件。
    try:
        if DURATION:
            t0 = time.time()
            while time.time() - t0 < DURATION:
                time.sleep(0.5)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print()
    finally:
        if td is not None:
            print("[*] 停止 tcpdump 并拉回 pcap...")
            size = stop_tcpdump(td)
            print("[*] %s  (%s bytes)" % (PCAP_OUT, size))
        print("[*] 收工：%d 条密钥 -> %s" % (n_keys, OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())