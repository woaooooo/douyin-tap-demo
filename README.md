# douyin-tap-demo

> **免责声明**：本项目仅供在自有设备或已获明确授权的环境中进行安全研究与协议分析。
> 使用者必须遵守当地法律、平台服务条款和隐私政策。
> **禁止**用于未授权访问、批量抓取、账号盗用、侵犯隐私或商业牟利。
> 作者不对任何滥用或损失负责。
>
> `out/httptap.log`、`out/sslkeylog.txt`、`out/*.pcap` 可能包含账号凭证、
> TLS 会话密钥和隐私数据。**不要提交、不要公开、不要分享给第三方。**

Android App HTTP/2 明文抓取工具链。

不依赖 pcap 解密、不依赖 Wireshark、不依赖中间人代理，
直接 hook 进程内的 `SSL_read` / `SSL_write`，自己做 HTTP/2 流重组 +
HPACK 解码 + body 解压，实时输出**明文**的 API 请求与响应。

> 本项目最初以 **抖音 / TikTok（`com.ss.android.ugc.aweme`）** 为研究对象开发，
> 因为它同时踩中了三套 SSL 栈、HPACK 动态表、zstd/gzip body 等多个硬骨头。
> 现在它是一个通用的 Android HTTP/2 协议分析工具，目标 App 通过 `--pkg` 指定。

```
### REQ  <host><path>?<query>
    content-length: 140 | x-tt-request-tag: t=0;n=0;s=0;p=0 | ...
    body[REQ sid=17 159B] {...}
--- RESP sid=17  status=200
    body[RESP sid=17 456B] {...}
```

配套还提供一条独立的 pcap + TLS keylog 采集链路，用于需要包级别细节的场景。

---

## 这个项目展示了什么

面试中讲这个项目时，可以强调这几点：

- **TLS 层**：不依赖中间人代理、不依赖 sslpinning bypass 补丁，
  直接在进程内 hook 多套独立 SSL 栈的 `SSL_read` / `SSL_write`，
  拿到握手后的明文。
- **HTTP/2 层**：自己实现流重组 + HPACK 解码（静态表 + 动态表 + Huffman），
  处理 `SSL_read` 返回半帧 / 多帧、CONTINUATION 帧、HEADERS 优先级字段等边界。
- **协议识别**：区分 h2 / h1，识别 HTTP/2 preface，处理 attach 前已建立的连接。
- **压缩**：请求 zstd、响应 gzip，跨 DATA 帧攒齐后按 `END_STREAM` 解压。
- **工程实践**：模块懒加载轮询、会话去重、keylog 回调注册、
  pcap 与 keylog 覆盖率对账。
- **逆向调试方法**：从“疑似 XOR 混淆”一路定位到“HPACK Huffman 码表错位 194/256 项”，
  并用参考实现（Python `hpack` 库）验证，而不是靠肉眼猜。

---

## 研究案例：抖音 / TikTok

抖音 / TikTok 这个目标有几个值得记录的坑，也是这个项目技术含量的来源。
完整分析见 [TUTORIAL.md](TUTORIAL.md)，这里只列要点：

1. **spawn 被拦死** —— `frida.spawn` 卡在 launch 阶段，只能改成 attach。
2. **进程名是 GBK** —— `dev.enumerate_processes()` 读出来是乱码，
   必须用 `adb shell pidof` 拿 PID。
3. **三套独立 SSL 栈** —— 必须同时覆盖，少一个就有流量抓不到。
4. **HPACK Huffman 码表错位** —— 自实现解码器解出乱码，
   误判成“XOR 1 混淆”，最后用 Python `hpack` 参考库验证是码表错位。
5. **SSL_read 返回半个帧** —— 必须按 `(连接, 方向)` 缓冲，
   HPACK 动态表在请求/响应两个方向各自独立。
6. **body 是压缩的** —— 请求 zstd、响应 gzip，且跨多个 DATA 帧。
7. **QUIC 实测不走** —— 封禁 UDP/443 后三组测试流量全为 0，
   `SSL_read/write` 覆盖 TCP 即可拿到目标 API。

---

## 环境要求

| 项 | 版本 / 说明 |
|---|---|
| 设备 | 已 root 的 Android 设备 |
| frida-server | 17.17.0（与 frida-python 版本必须一致） |
| frida-python | 17.17.0 |
| Python | 3.13 |
| 依赖 | `pip install -r requirements.txt` |

`hpack` 和 `zstandard` 只在辅助工具里用（参考解码验证 / body 解压）。

---

## 快速开始

```powershell
# 1. 设备侧准备
adb forward tcp:8888 tcp:8888          # frida-server 端口转发
adb shell "su -c '/data/local/tmp/Tool/fs &'"   # 启动 frida-server（改名版）

# 2. 抓包（会自动重启目标 App 并 attach）
#    以抖音为例：
py httptap.py --pkg com.ss.android.ugc.aweme --duration 90
```

输出实时打印到控制台，同时写入 `out/httptap.log`。

详见 [TUTORIAL.md](TUTORIAL.md)。

---

## 文件说明

```
douyin-tap-demo/
├── README.md            本文件 —— 技术总结
├── TUTORIAL.md          使用教程
├── requirements.txt     Python 依赖
├── httptap.py           ★ 主程序：HTTP/2 明文抓取运行器
├── js/
│   ├── httptap.js       ★ 主 hook：SSL_read/write + 流重组 + HPACK
│   └── keylog.js        TLS keylog hook（给 pcap 解密用）
├── spawn_keylog.py      备用链路：抓包 + keylog -> Wireshark 解密
├── verify_keylog.py     对账工具：pcap 与 keylog 的覆盖率
└── out/                 输出目录（自动创建，已加入 .gitignore）
    ├── httptap.log
    ├── target.pcap
    └── sslkeylog.txt
```

> `spawn_keylog.py` 名字里的 "spawn" 是历史遗留 —— 它**不用** spawn（见下文坑 1）。

---

## 技术总结

### 目标进程的实际情况

attach 后枚举模块，抖音有三套**独立的** SSL 栈，必须全部覆盖。
具体库名见 `js/httptap.js` 顶部的 `TARGETS` 数组注释。
如果你的目标 App 用了别的命名，先跑一遍模块扫描：

```javascript
Process.enumerateModules().forEach(m => {
  const n = m.name.toLowerCase();
  if (n.includes("ssl") || n.includes("boring") || n.includes("cronet"))
    console.log(m.name, m.base, m.size);
});
```

导出符号实测（这决定了 hook 策略）：

| 符号 | 状态 |
|---|---|
| `SSL_set_keylog_callback` | ❌ 被 strip |
| `SSL_CTX_set_keylog_callback` | ✅ |
| `SSL_get_SSL_CTX` | ✅ 关键 |
| `SSL_read` / `SSL_write` | ✅ |
| `SSL_do_handshake` / `SSL_new` / `SSL_CTX_new` | ✅ |

---

### 坑 1：spawn 被目标 App 拦死

```python
dev.spawn(["com.ss.android.ugc.aweme"])
# -> frida.TimedOutError: unexpectedly timed out while waiting for app to launch
```

对照实验确认这是抖音特有的：

| 目标 | 结果 |
|---|---|
| `com.android.settings` | ✅ 正常启动、脚本加载、存活 |
| `com.ss.android.ugc.aweme` | ❌ 卡死在 launch 阶段 |

排除版本问题（server 与 python 都是 17.17.0）。

**对策**：不 spawn。自己启动 App，等它跑起来再 attach。实测 attach 成功且 App 不崩。

---

### 坑 2：进程名是 GBK，frida 读出来是乱码

```python
dev.enumerate_processes()
# -> 18899 '????'        ← 抖音本体
```

抖音把进程名 `PR_SET_NAME` 成了 **GBK 编码的「抖音」**，frida 按 UTF-8 解码就成了乱码。
所以 `p.name == "com.ss.android.ugc.aweme"` 和 `p.name == "抖音"` **永远匹配不上**。

**对策**：用 `adb shell pidof`（读 cmdline）拿 PID。

---

### 坑 3：核心 hook 因为一个不存在的符号被整段跳过

`SSL_set_keylog_callback` 在这个 build 里不存在，于是：

```javascript
var origSetSslKl = setSslKlPtr ? ... : null;   // null
if (hsPtr && origSetSslKl) { ... }             // 永不执行
```

**本该是主力的 `SSL_do_handshake` hook，从来没装上过。**

**对策**：用 `SSL_get_SSL_CTX(ssl)` 把 `SSL*` 转成 `SSL_CTX*`，改调 CTX 级 API。
这个 hook 是 attach 模式的关键 —— 注入时绝大多数 CTX 早就 `SSL_CTX_new` 过了。

---

### 坑 4：HPACK Huffman 码表整体错位一格 ★

**这是最花时间的一个。** 现象是解出来的 header 里混着反引号和 `@`，看起来像被某种变换处理过：

```
raw: cookie: <COOKIE>
```

一度误判成"抖音做了 XOR 1 混淆"（因为 `` ` `` 和 `a` 只差一位，且把 `` ` `` 换成 `a` 后那段值恰好是合法 hex），还写了个 `fix()` 去"还原"——**那是在把正确数据改坏**。

**真正的原因**：Huffman 码表从符号 62 起整体错位：

```
sym  62 ('>'): 0xffd/12    应为 0xffb/12
sym  63 ('?'): 0x1ffa/13   应为 0x3fc/10
sym  64 ('@'): 0x21/6      应为 0x1ffa/13
...
不一致条目数: 194 / 256
```

错位产生的字符恰好和正确字符相差 ±1，所以看着"像混淆"。

**判定方式 —— 不要靠肉眼猜，用参考实现**：把原始 header block 的 hex 交给 Python 标准 `hpack` 库：

```
:status: 200
server: <server>
content-type: application/json; charset=utf-8
x-tt-logid: <LOGID>
```

干净的标准 HPACK，**wire 上没有任何混淆**。换掉码表后一切正常，`fix()` 直接删除。

> 这个教训值得记住：拿不准的编码问题，先用参考实现跑一遍，比对着输出猜变换快得多。

---

### 坑 5：SSL_read / SSL_write 会返回半个帧

`SSL_read` 按任意块返回，一次调用可能含**多个** HTTP/2 帧、也可能是**半个**帧：

```
R[...] n=8192  00 02 8d 01 04 ...   ← 8192 是单次上限，大响应被切开
R[...] n=1000  82 7e 04 9f 08 ...   ← 开头不是帧头，这是上一个帧的后半截
```

**对策**：按 `(连接, 方向)` 缓冲，攒够完整帧再解析。

**另一个隐患**：HPACK 动态表在**请求/响应两个方向各自独立**，所以缓冲和动态表的 key 都必须带方向。

---

### 坑 6：body 是压缩的

| 方向 | 编码 | magic |
|---|---|---|
| 请求 | zstd | `28 b5 2f fd` |
| 响应 | gzip | `1f 8b 08` |

body 还会跨多个 DATA 帧，必须**攒齐后**再解压（等到 `END_STREAM`）。
所以 JS 侧一律把原始字节以 hex 交给 Python，不做可打印性判断。

---

### 关于 QUIC：实测抖音不走

设备上曾用 iptables 封禁 UDP/443 以强制走 TCP。实测结论：

```bash
# 封禁规则（v4 + v6 都要）
iptables  -I OUTPUT 1 -p udp --dport 443 -j DROP
ip6tables -I OUTPUT 1 -p udp --dport 443 -j DROP

# 计数器增量连续 25s 为 +0：抖音试过（累计 63/117 包）被拦后就不再重试
```

**解封 QUIC 后做了三组测试，UDP/443 流量全部为 0**：

| 场景 | UDP/443 |
|---|---|
| 重启 App 观察 30s | 0 |
| 浏览信息流 40s | 0 |
| 打开直播间、`LivePlayActivity` 前台播放 | 0 |

直播流量实测走 TCP（IPv6 443），且全程没有任何连向远端的 UDP socket。

> **注意混淆因素**：抖音曾尝试 QUIC 63 次被拦，TTNet 把失败状态持久化了。
> 所以准确结论是"在当前状态下不用 QUIC"，而非"从不使用"。
> 要真正证伪需要 `pm clear`（会退出登录），没有做。

技术层面，抖音的 QUIC 库**动态链接其 boringssl**（不是自带密码库），
所以 keylog 方案理论上能覆盖 QUIC 密钥。但真要走这条路还要重写 QPACK（HTTP/3 的头压缩），
且 keylog 的标识字段在 QUIC 下是 DCID 而非 TLS random，需要实测。

**结论：对"拿到 API"这个目标，QUIC 这条路收益为零 —— 没有 QUIC 可逆。**

---

## 验证数据

| 指标 | 数值 |
|---|---|
| HTTP/2 抓取（30~45s） | 160~280 请求 / 87~144 body |
| pcap 可解密覆盖率 | 90.5%（`-i any`）/ 93.1%（`wlan0`） |
| 覆盖的 SSL 栈 | 3/3 |

覆盖率由 `verify_keylog.py` 给出 —— 从 pcap 里提取每个 TLS ClientHello 的
client_random，与 keylog 对账，等价于"Wireshark 能解开多少"。

剩余 ~7% 来自静态链接 boringssl 的库 —— 符号没导出，挂不上。

---

## 已知局限

- **`:authority` 有时为空** —— attach 前已建立的连接，HPACK 动态表状态不同步，
  部分字段（尤其 `:authority`）会丢。同连接上首个能解出的请求可以补主机名。
- **body 单帧上限 256KB**，超出会截断导致解压失败。
- **QUIC / UDP 不覆盖** —— `SSL_read/write` 只覆盖 TCP；UDP 数据面（如 P2P 加速的
  port 3017）抓不到。
- **App 重启需重新 attach** —— 脚本已自动处理。
- **仅验证于 frida 17.17.0**，其他版本符号导出可能有差异，先跑一遍模块扫描确认。