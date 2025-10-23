# WireCrab 实施计划

## 实施原则
1. **MVP优先** - 先实现最小可行产品，验证架构设计
2. **模块化设计** - 保持核心逻辑与UI分离，便于后续添加GUI
3. **迭代开发** - 分阶段实现，每阶段都能运行和测试

## 实施阶段

### 第一阶段：基础框架（原型）
1. 更新Cargo.toml，添加基本依赖
2. 实现CLI参数结构
3. 创建基本模块结构
4. 实现网络接口列举功能
5. 实现简单的数据包捕获和显示

### 第二阶段：协议解析
1. 实现以太网层解析
2. 实现IPv4基本解析（先不考虑IPv6）
3. 实现TCP/UDP解析
4. 实现基本的JSON输出

### 第三阶段：过滤功能
1. 实现协议类型过滤
2. 实现IP地址过滤
3. 实现端口过滤
4. 集成过滤器到捕获流程

### 第四阶段：应用层协议（可选）
1. 实现HTTP基本解析
2. 实现DNS解析
3. 添加会话追踪基础

### 第五阶段：完善和优化
1. 添加错误处理
2. 完善输出格式
3. 添加基本测试
4. 编写使用文档

## 代码结构设计（便于GUI扩展）

```rust
// lib.rs - 核心库，与UI无关
pub mod capture;
pub mod parser;
pub mod filter;
pub mod output;
pub mod session;

// main.rs - CLI入口
// 未来可以创建 gui/main.rs 作为GUI入口
```

## 原型版本依赖（精简版）

```toml
[dependencies]
clap = { version = "4.5", features = ["derive"] }
etherparse = "0.15"
pcap = "2.2"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = "0.4"
anyhow = "1.0"
```

## 第一个里程碑目标
能够运行以下命令并看到JSON格式的数据包信息：
```bash
wirecrab -i eth0 --protocol tcp --port 80
```

输出示例：
```json
{
  "timestamp": "2024-10-21T12:34:56Z",
  "protocol": "TCP",
  "src_ip": "192.168.1.100",
  "dst_ip": "93.184.216.34",
  "src_port": 54321,
  "dst_port": 80,
  "length": 60
}
```

## 注意事项
1. 保持接口清晰，便于GUI调用
2. 使用Result<T, E>处理错误，避免panic
3. 核心逻辑不依赖任何UI相关的代码
4. 使用trait定义输出接口，便于扩展不同的输出格式