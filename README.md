# WireCrab 🦀

WireCrab 是一个基于 Rust 开发的网络数据包嗅探工具，支持实时捕获、解析和过滤网络流量。

## 功能特性

- ✅ 支持多种协议解析：IPv4、TCP、UDP、ARP、ICMP（原型版本）
- ✅ 灵活的命令行过滤：按协议类型、IP地址、端口等过滤
- ✅ JSON 格式输出，便于后续处理和分析
- ✅ 跨平台支持（Linux、Windows、macOS）
- 🚧 IPv6 支持（计划中）
- 🚧 应用层协议解析：HTTP、DNS 等（计划中）
- 🚧 会话追踪功能（计划中）

## 安装

### 从源码构建

需要先安装 Rust 工具链：

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 克隆项目
git clone https://github.com/yourusername/wirecrab.git
cd wirecrab

# 构建项目
cargo build --release

# 二进制文件位于 target/release/wirecrab
```

### 依赖要求

- Rust 1.70+
- libpcap（Linux/macOS）或 WinPcap/Npcap（Windows）
- 需要 root/管理员权限来捕获网络数据包

在 Ubuntu/Debian 上安装 libpcap：
```bash
sudo apt-get install libpcap-dev
```

在 macOS 上安装 libpcap：
```bash
brew install libpcap
```

## 使用方法

### 基本用法

```bash
# 列出所有可用的网络接口
wirecrab --list-interfaces

# 在默认接口上捕获数据包
sudo wirecrab

# 在指定接口上捕获数据包
sudo wirecrab -i eth0

# 捕获指定数量的数据包
sudo wirecrab -c 10

# 将输出保存到文件
sudo wirecrab -o packets.json
```

### 过滤选项

```bash
# 按协议类型过滤
sudo wirecrab --protocol tcp

# 按源IP地址过滤
sudo wirecrab --src-ip 192.168.1.100

# 按目标IP地址过滤
sudo wirecrab --dst-ip 8.8.8.8

# 按端口过滤（TCP/UDP）
sudo wirecrab --port 80
sudo wirecrab --src-port 443
sudo wirecrab --dst-port 22

# 组合过滤
sudo wirecrab --protocol tcp --dst-port 443 --src-ip 192.168.1.100
```

### 命令行参数

```
选项:
  -i, --interface <INTERFACE>  网络接口名称 (默认: 自动选择第一个可用接口)
  -c, --count <COUNT>          捕获数据包数量 (默认: 无限)
  -o, --output <OUTPUT>        输出到文件 (默认: stdout)
      --protocol <PROTOCOL>    协议类型过滤 (tcp|udp|arp|icmp|igmp)
      --src-ip <SRC_IP>        源IP地址过滤
      --dst-ip <DST_IP>        目标IP地址过滤
      --src-port <SRC_PORT>    源端口过滤 (仅TCP/UDP)
      --dst-port <DST_PORT>    目标端口过滤 (仅TCP/UDP)
      --port <PORT>            端口过滤 (源或目标)
  -l, --list-interfaces        列出所有网络接口
  -v, --verbose                详细输出模式
  -h, --help                   显示帮助信息
  -V, --version                显示版本信息
```

## 输出格式

WireCrab 使用 JSON 格式输出捕获的数据包信息：

```json
{
  "timestamp": "2025-10-22T05:24:47.884393077+00:00",
  "interface": "eth0",
  "length": 98,
  "frame_number": 1,
  "link_layer": {
    "protocol": "Ethernet",
    "src_mac": "00:15:5D:F7:59:2F",
    "dst_mac": "00:15:5D:9E:65:1B"
  },
  "network_layer": {
    "protocol": "IPv4",
    "src_ip": "172.23.121.133",
    "dst_ip": "198.18.1.220",
    "ttl": 64,
    "id": 61566,
    "flags": ["DF"],
    "fragment_offset": 0,
    "total_length": 84
  },
  "transport_layer": {
    "protocol": "TCP",
    "src_port": 54321,
    "dst_port": 443,
    "seq": 1234567890,
    "ack": 0,
    "flags": ["SYN"],
    "window": 65535,
    "checksum": 0,
    "urgent_pointer": 0
  }
}
```

## 使用示例

### 1. 监控 HTTP 流量

```bash
sudo wirecrab --protocol tcp --port 80
```

### 2. 监控 HTTPS 流量

```bash
sudo wirecrab --protocol tcp --port 443
```

### 3. 监控特定主机的所有流量

```bash
sudo wirecrab --src-ip 192.168.1.100
# 或
sudo wirecrab --dst-ip 192.168.1.100
```

### 4. 保存捕获结果供后续分析

```bash
sudo wirecrab -c 1000 -o capture.json
# 使用 jq 分析 JSON 数据
cat capture.json | jq '.transport_layer.protocol' | sort | uniq -c
```

### 5. 监控 DNS 查询

```bash
sudo wirecrab --protocol udp --port 53
```

## 开发

### 项目结构

```
wirecrab/
├── src/
│   ├── main.rs              # 程序入口，CLI参数处理
│   ├── lib.rs               # 库入口
│   ├── capture/             # 数据包捕获模块
│   │   ├── mod.rs
│   │   └── device.rs        # 网络接口管理
│   ├── parser/              # 协议解析模块
│   │   ├── mod.rs
│   │   ├── ethernet.rs      # 以太网层解析
│   │   ├── ipv4.rs          # IPv4协议解析
│   │   ├── tcp.rs           # TCP协议解析
│   │   └── udp.rs           # UDP协议解析
│   ├── filter/              # 过滤器模块
│   │   ├── mod.rs
│   │   └── rules.rs         # 过滤规则定义
│   └── output/              # 输出格式化模块
│       ├── mod.rs
│       └── json.rs          # JSON格式化器
├── Cargo.toml               # 项目配置
├── architecture.md          # 架构设计文档
└── implementation-plan.md   # 实施计划
```

### 运行测试

```bash
cargo test
```

### 构建调试版本

```bash
cargo build
```

### 构建发布版本

```bash
cargo build --release
```

## 注意事项

1. **权限要求**：网络数据包捕获需要 root/管理员权限
2. **性能影响**：在高流量环境下可能会影响系统性能
3. **隐私安全**：请遵守相关法律法规，仅在授权的网络环境中使用
4. **数据量**：长时间运行会产生大量数据，建议使用过滤器和计数限制

## 贡献

欢迎提交 Issue 和 Pull Request！

### 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 开启 Pull Request

## 路线图

- [x] 基础数据包捕获功能
- [x] IPv4 协议解析
- [x] TCP/UDP 协议解析
- [x] 基本过滤功能
- [x] JSON 输出格式
- [ ] IPv6 支持
- [ ] 应用层协议解析（HTTP、DNS、FTP等）
- [ ] 会话追踪和流重组
- [ ] 数据包统计功能
- [ ] GUI 界面支持
- [ ] PCAP 文件读写支持
- [ ] 性能优化（多线程、零拷贝）

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情

## 致谢

- [pcap](https://github.com/rust-pcap/pcap) - Rust pcap 库
- [etherparse](https://github.com/JulianSchmid/etherparse) - 以太网和 IP 协议解析库
- [clap](https://github.com/clap-rs/clap) - 命令行参数解析库

## 联系方式

- 项目主页：[https://github.com/yourusername/wirecrab](https://github.com/yourusername/wirecrab)
- Issue 跟踪：[https://github.com/yourusername/wirecrab/issues](https://github.com/yourusername/wirecrab/issues)