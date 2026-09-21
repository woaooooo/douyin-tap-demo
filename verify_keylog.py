"""
对账 pcap 和 sslkeylog.txt

从 pcap 里把每个 TLS ClientHello 的 client_random 抠出来，
看在 keylog 里能不能找到对应密钥 —— 这直接等于"Wireshark 能解开多少"。

用法：
    py verify_keylog.py
    py verify_keylog.py other.pcap other.txt
"""

import os
import struct
import sys

BASE = os.path.dirname(os.path.abspath(__file__))

PCAP = sys.argv[1] if len(sys.argv) > 1 else os.path.join(BASE, "out", "target.pcap")
KEYLOG = sys.argv[2] if len(sys.argv) > 2 else os.path.join(BASE, "out", "sslkeylog.txt")


def client_hellos(path):
    raw = open(path, "rb").read()
    magic, vmaj, vmin, tz, sig, snap, link = struct.unpack("<IHHiIII", raw[:24])
    print("pcap: linktype=%d version=%d.%d" % (link, vmaj, vmin))

    off, n_pkt, randoms = 24, 0, []
    while off + 16 <= len(raw):
        ts, tus, incl, orig = struct.unpack("<IIII", raw[off:off + 16])
        off += 16
        pkt = raw[off:off + incl]
        off += incl
        n_pkt += 1

        if link == 276:      # LINUX_SLL2
            if len(pkt) < 20:
                continue
            ether, p = struct.unpack(">H", pkt[0:2])[0], pkt[20:]
        elif link == 113:    # LINUX_SLL
            ether, p = struct.unpack(">H", pkt[14:16])[0], pkt[16:]
        elif link == 1:      # EN10MB
            ether, p = struct.unpack(">H", pkt[12:14])[0], pkt[14:]
        else:
            continue

        if ether == 0x0800:
            if len(p) < 20 or p[9] != 6:      # IPv4 + TCP
                continue
            p = p[(p[0] & 0xF) * 4:]
        elif ether == 0x86DD:
            if len(p) < 40 or p[6] != 6:      # IPv6 + TCP
                continue
            p = p[40:]
        else:
            continue

        if len(p) < 20:
            continue
        payload = p[(p[12] >> 4) * 4:]

        # TLS record: type=0x16(handshake), version, len;  handshake type=0x01(ClientHello)
        if len(payload) > 43 and payload[0] == 0x16 and payload[5] == 0x01:
            randoms.append(payload[11:43].hex())

    return n_pkt, randoms


def load_keys(path):
    keys = set()
    for line in open(path, encoding="utf-8"):
        f = line.split()
        if len(f) == 3:
            keys.add(f[1])
    return keys


n_pkt, randoms = client_hellos(PCAP)
keys = load_keys(KEYLOG)
uniq = set(randoms)
matched = uniq & keys

print("packets           = %d" % n_pkt)
print("ClientHellos      = %d" % len(randoms))
print("unique randoms    = %d" % len(uniq))
print("keylog entries    = %d" % len(keys))
print("matched           = %d" % len(matched))
print("unmatched         = %d" % len(uniq - keys))
print()
if uniq:
    print("可解密覆盖率 = %.1f%%" % (100.0 * len(matched) / len(uniq)))
    if len(uniq) - len(matched):
        print()
        print("未匹配的 random（这些流 Wireshark 解不开）：")
        for r in sorted(uniq - keys)[:10]:
            print("   " + r)