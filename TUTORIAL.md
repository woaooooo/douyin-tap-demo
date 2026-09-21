# 使用教程

从零到抓到目标 App API 明文的完整流程。

以 **抖音 / TikTok（`com.ss.android.ugc.aweme`）** 为例。

---

## 0. 一次性准备

### 0.1 主机侧

```powershell
pip install -r requirements.txt
py -c "import frida; print(frida.__version__)"     # 记下版本号
```

### 0.2 设备侧

设备需已 root。frida-server 的**版本必须与 frida-python 完全一致**。

```powershell
# 推送 frida-server（建议改名，降低被杀概率）
adb push frida-server-17.17.0-android-arm64 /data/local/tmp/Tool/fs
adb shell "su -c 'chmod 755 /data/local/tmp/Tool/fs'"

# 启动
adb shell "su -c '/data/local/tmp/Tool/fs &'"

# 端口转发
adb forward tcp:8888 tcp:8888

# 验证
py -c "import frida; d=frida.get_device_manager().add_remote_device('127.0.0.1:8888'); print(len(d.enumerate_processes()), 'procs')"
```

> **为什么改名成 `fs`**：抖音有反调试，会扫进程列表找 `frida-server`。
> 但注意 —— 改名只骗过进程名匹配，frida 内部的线程名（`gum-js-loop` 等）和
> 内存里的字符串没变，所以这层掩盖是**不完整**的。实测 attach 仍能成功，够用。

---

## 1. 封禁 QUIC（**推荐，务必先做**）

抖音会尝试 QUIC（UDP/443）。走 QUIC 的流量 `SSL_read/write` 抓不到，会静默丢失。

**抓包前先封掉，强制它走 TCP：**

```powershell
# IPv4
adb shell "su -c 'iptables -I OUTPUT 1 -p udp --dport 443 -j DROP'"
# IPv6
adb shell "su -c 'ip6tables -I OUTPUT 1 -p udp --dport 443 -j DROP'"
```

顺带把常见 P2P 端口也封掉（可选）：

```powershell
adb shell "su -c 'iptables -I OUTPUT 1 -p udp --dport 80 -j DROP'"
adb shell "su -c 'iptables -I OUTPUT 1 -p udp --dport 8889 -j DROP'"
adb shell "su -c 'iptables -I OUTPUT 1 -p udp --dport 13011 -j DROP'"
```

### 确认封禁生效

```powershell
# 记下计数
adb shell "su -c 'iptables -L OUTPUT -n -v | grep -E \"DROP.*udp\"'"
# 等 30 秒
Start-Sleep 30
# 再看：增量不为 0 说明抖音在尝试 QUIC 且被拦（正常）
adb shell "su -c 'iptables -L OUTPUT -n -v | grep -E \"DROP.*udp\"'"
```

增量连续为 **0** 说明抖音已经放弃 QUIC、老实走 TCP —— 这正是我们要的状态。

### 用完解封

```powershell
adb shell "su -c 'iptables  -D OUTPUT -p udp --dport 443 -j DROP'"
adb shell "su -c 'ip6tables -D OUTPUT -p udp --dport 443 -j DROP'"
# 其余同理替换端口号
```

> **别提前解封**。抖音的 QUIC 失败状态是持久化的，解封后它**不会**立刻重试 ——
> 但一旦清数据或冷却期过期，QUIC 就会回来，抓包链路又会漏流量。

---

## 2. 抓包

```powershell
cd douyin-tap-demo

# 自动重启抖音 -> attach -> 抓 90 秒
py httptap.py --pkg com.ss.android.ugc.aweme --duration 90

# 或：只 attach 当前已在运行的抖音，Ctrl+C 结束
py httptap.py --pkg com.ss.android.ugc.aweme --attach
```

脚本会：

1. `force-stop` 目标 App
2. 用 `monkey` 启动它
3. 轮询 `adb shell pidof` 拿到 PID
4. 等 3 秒（`--wait` 可调）后 attach
5. hook 三套 SSL 栈的 `SSL_read` / `SSL_write`
6. 实时输出明文，同时写 `out/httptap.log`

成功时你会看到：

```
[*] pid = 10964，等 3.0s
[*] attaching...
[*] libttboringssl.so hooked (w=true r=true)
[*] stable_cronet_libssl.so hooked (w=true r=true)
[*] libssl.so hooked (w=true r=true)
[*] httptap loaded -> douyin-tap-demo/out/httptap.log
```

**三个模块全部 `hooked` 才说明链路完整。** 少一个就意味着有流量抓不到。

> 抖音的库名在 `js/httptap.js` 顶部 `TARGETS` 数组的注释里。
> 默认只挂了通用名（`libssl.so` / `libboringssl.so` / `cronet_libssl.so`），
> 针对抖音需要手动把 `libttboringssl.so`、`stable_cronet_libssl.so` 加进去。

### 抓到什么内容

attach 完成后去操作抖音（刷信息流、进直播间、点开评论），流量就会持续落盘。

---

## 3. 读输出

### 3.1 只看 API 端点

CDN 图片会把列表淹掉，滤一下：

```powershell
Select-String -Path out\httptap.log -Pattern '^### REQ' |
  ForEach-Object { $_.Line -replace '^### REQ  ','' -replace '\?.*','' } |
  Where-Object { $_ -notmatch 'douyinpic|douyinstatic|byteimg|bytegecko|\.(heic|jpe?g|png|mp4|m4a|webp|json)' } |
  Sort-Object -Unique
```

### 3.2 输出格式

```
### REQ  <主机名><路径>          ← 请求行（含全部查询参数）
    <关键请求头>
    body[REQ sid=N 123B] {...}   ← 解压后的请求体
--- RESP sid=N  status=200       ← 响应状态
    body[RESP sid=N 456B] {...}  ← 解压后的响应体
```

### 3.3 两个已知现象

- **主机名为空**（`### REQ  /aweme/v2/...`）—— 该连接的 HPACK 动态表在 attach 前就已建立，
  状态不同步，`:authority` 丢了。同一条连接上前面的请求能补上主机名。
- **body 显示 `hex:`** —— 该 body 不是可识别的压缩格式（可能是 protobuf 或二进制），
  或是超大 body 被 256KB 截断。hex 前缀是原始字节。

---

## 4. 备用链路：pcap + TLS keylog

需要包级别细节（重传、时序）时才用。会同时产出 `out/target.pcap` 和 `out/sslkeylog.txt`。

```powershell
py spawn_keylog.py --pkg com.ss.android.ugc.aweme --duration 90
```

它会自己起停设备上的 tcpdump，**且 tcpdump 在 attach 成功之后才启动** ——
保证 pcap 里每条 TLS 连接都有对应密钥，不会出现"有密文没密钥"。

### 对账（重要）

```powershell
py verify_keylog.py
```

```
packets           = 9414
ClientHellos      = 30
matched           = 27
可解密覆盖率 = 93.1%
```

这个数字**等价于"Wireshark 能解开多少"** —— 它从 pcap 里抠出每个 ClientHello 的
client_random 跟 keylog 对账。覆盖率明显偏低就说明有 SSL 栈没挂上。

### Wireshark 配置

```
Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename
    -> <项目目录>/out/sslkeylog.txt
```

然后打开 `out/target.pcap`，过滤器用 `http2 or http`。

**如果报 unknown link type**：默认 `-i any` 产出 LINUX_SLL2 帧（linktype=276），
Wireshark 4.0+ 才认。老版本加 `--iface wlan0` 生成普通以太网帧。
但注意 `wlan0` 抓不到蜂窝数据，手机切到流量时什么都抓不到。

---

## 5. 故障排查

### attach 后抖音闪退 / 卡死

先确认是不是 spawn 导致的。本项目已改用 attach，若仍崩，说明该版本的反调试策略变了：

```powershell
# 对照实验：同一套 frida 能否正常 spawn 一个普通 App
py -c "
import frida, time
d = frida.get_device_manager().add_remote_device('127.0.0.1:8888')
pid = d.spawn(['com.android.settings']); s = d.attach(pid)
s.create_script('console.log(\"ok\")').load(); d.resume(pid); time.sleep(3)
print('settings spawn OK -> frida 本身没问题，是抖音特有防护')
"
```

### 只抓到一个模块 / 一个都没抓到

模块是**懒加载**的，cronet 尤其如此。`httptap.js` 每 300ms 轮询一次，正常情况下
cronet 模块会在首次网络请求时被挂上。如果始终只有一个，说明该版本换了 SSL 库 ——
跑一遍模块扫描确认导出符号：

```javascript
Process.enumerateModules().forEach(m => {
  const n = m.name.toLowerCase();
  if (n.includes("ssl") || n.includes("boring") || n.includes("cronet"))
    console.log(m.name, m.base, m.size);
});
```

确认后改 `js/httptap.js` 顶部的 `TARGETS` 数组。

### 全是乱码

**先怀疑 HPACK 码表**，不要猜"混淆"。拿原始 header block 的 hex 交给参考实现验证：

```python
import hpack
print(hpack.Decoder().decode(bytes.fromhex("<你的header block hex>"), raw=True))
```

参考库解出来是干净的 `:status` / `server` / `content-type`，就说明 wire 没问题，
是我们的解码器有 bug —— 去比对 `js/httptap.js` 里的 `HUF` 表：

```python
import hpack.huffman_constants as hc
# 逐符号对比 REQUEST_CODES / REQUEST_CODES_LENGTH
```

### 设备上残留 tcpdump 进程

手动跑 `tcpdump` 时如果用 `timeout` 从主机侧掐，**adb 客户端被杀但设备上的
tcpdump 会活下来**，而且新起的实例会和它抢同一个输出文件。

```powershell
# 查看
adb shell "su -c 'pgrep -l tcpdump'"
# 清理（-INT 让它正常收尾刷盘，再 -9 兜底）
adb shell "su -c 'pkill -INT tcpdump; sleep 1; pkill -9 tcpdump'"
```

`spawn_keylog.py` 已在启动时自动做这件事。手动跑 tcpdump 时请注意。

### 抓到的全是 CDN / 没有 API

- 确认封了 QUIC（第 1 节）
- 确认三个模块都 `hooked`
- 确认报错信息里没有 `session detached`（有的话说明 App 被杀了）

---

## 6. 清理

### 主机侧

```powershell
Remove-Item douyin-tap-demo\out\* -Force        # 清输出
```

### 设备侧

```powershell
# 结束残留 tcpdump
adb shell "su -c 'pkill -INT tcpdump; sleep 1; pkill -9 tcpdump'"
# 删掉抓包文件
adb shell "su -c 'rm -f /data/local/tmp/target.pcap'"
# 按需解封 QUIC（见第 1 节）
```

### 结束 frida-server

```powershell
adb shell "su -c 'pkill -f /data/local/tmp/Tool/fs'"
adb forward --remove tcp:8888
```

---

## 7. 命令速查

| 目的 | 命令 |
|---|---|
| 抓明文 API | `py httptap.py --pkg com.ss.android.ugc.aweme --duration 90` |
| attach 已运行的抖音 | `py httptap.py --pkg com.ss.android.ugc.aweme --attach` |
| 抓 pcap + keylog | `py spawn_keylog.py --pkg com.ss.android.ugc.aweme --duration 90` |
| 验算解密覆盖率 | `py verify_keylog.py` |
| 封 QUIC | `adb shell "su -c 'iptables -I OUTPUT 1 -p udp --dport 443 -j DROP'"` |
| 解封 QUIC | `adb shell "su -c 'iptables -D OUTPUT -p udp --dport 443 -j DROP'"` |
| 清残留 tcpdump | `adb shell "su -c 'pkill -9 tcpdump'"` |

### `httptap.py` 参数

| 参数 | 说明 |
|---|---|
| `--pkg <name>` | 目标 App 包名，**必填**。抖音为 `com.ss.android.ugc.aweme` |
| `--attach` | 不重启，只 attach 当前进程 |
| `--duration N` | N 秒后自动结束（默认 Ctrl+C） |
| `--wait N` | attach 前的等待秒数，默认 3.0。调小会提前介入，但可能踩到早期反调试检查 |