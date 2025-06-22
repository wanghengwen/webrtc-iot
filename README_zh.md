# webrtc-iot - 面向物联网/嵌入式设备的现代 C++ WebRTC 库

![build](https://github.com/wanghengwen/webrtc-iot/actions/workflows/build.yml/badge.svg)

webrtc-iot 是一个用 C++ 编写的现代 WebRTC 实现，专为物联网和嵌入式设备流媒体应用而设计。该库经过大量重构，提供了简洁的 C++ 接口，同时保持了在资源受限环境中的性能和可移植性。

> **致谢**: 本项目基于 @sepfy 的优秀项目 [libpeer](https://github.com/sepfy/libpeer)。我们对提供基础 WebRTC 实现的原作者表示诚挚的感谢，正是他们的工作使得这次 C++ 现代化改造成为可能。

## ✨ 主要特性

### 媒体支持
- **视频编解码器**
  - H.264，支持分片传输
  - 可配置帧率和码率
- **音频编解码器**  
  - G.711 PCM (A-law/µ-law)
  - OPUS，支持可配置码率
- **实时处理**
  - 优化的 RTP/RTCP 处理
  - 动态 SSRC 生成

### WebRTC 核心功能
- **端到端连接**
  - ICE (交互式连接建立)
  - STUN/TURN 服务器支持
  - IPv4/IPv6 双栈
- **安全性**
  - DTLS-SRTP 加密
  - 证书指纹验证
  - 安全密钥交换
- **数据通道**
  - 基于 SCTP 的可靠/不可靠消息传输
  - 支持二进制和文本数据
  - 每个连接支持多个通道

## 🏗️ 架构设计

### 现代 C++ 设计
- **RAII** 资源管理
- **智能指针** 确保内存安全
- **std::function** 回调函数，灵活的事件处理
- **命名空间组织** (`rtc::` 命名空间)
- **异常安全** 操作

### 项目结构
```
webrtc-iot/
├── include/           # 公共头文件 (C++ 和 C)
├── src/              # 实现文件
├── tests/            # 测试应用程序
└── third_party/      # 外部依赖
```

### 核心类
- `rtc::PeerConnection` - WebRTC 端到端连接主类
- `rtc::IceAgent` - ICE 连接管理  
- `rtc::RtpEncoder/RtpDecoder` - 媒体处理
- `rtc::DtlsSrtpSession` - 安全层
- `rtc::SctpAssociation` - 数据通道支持

## 📦 依赖库

| 库 | 用途 | 版本 |
|---------|---------|---------| 
| [mbedTLS](https://github.com/Mbed-TLS/mbedtls) | 加密和 TLS | 最新版 |
| [libsrtp](https://github.com/cisco/libsrtp) | SRTP 加密 | v2.x |
| [usrsctp](https://github.com/sctplab/usrsctp) | 数据通道 SCTP | 最新版 |

所有依赖库都通过 CMake 自动下载和构建。

## 🚀 快速开始

### 系统要求
```bash
sudo apt update && sudo apt install -y git cmake build-essential
```

### 构建和测试
```bash
# 克隆包含所有子模块的仓库
git clone --recursive https://github.com/wanghengwen/webrtc-iot
cd webrtc-iot

# 构建库和测试程序
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# 运行基本连接测试
./build/tests/test_agent

# 测试音频回声的端到端连接
./build/tests/test_peer_offer
```

### 基本使用示例

```cpp
#include "peer_connection.hpp"

int main() {
    // 配置端到端连接
    rtc::PeerConfiguration config;
    config.audio_codec = rtc::MediaCodec::PCMU;
    
    // 添加 STUN 服务器用于 NAT 穿透
    config.ice_servers.push_back({
        .urls = "stun:stun.l.google.com:19302"
    });
    
    // 创建端到端连接
    rtc::PeerConnection pc(config);
    
    // 设置回调函数
    pc.on_ice_connection_state_change([](rtc::PeerConnectionState state) {
        std::cout << "连接状态: " << static_cast<int>(state) << std::endl;
    });
    
    // 创建和处理 offer/answer
    std::string offer = pc.create_offer();
    std::cout << "本地 offer: " << offer << std::endl;
    
    return 0;
}
```

## 🧪 测试应用程序

项目包含多个演示不同功能的测试应用程序：

### 核心测试
- **`test_agent`** - ICE 代理和 STUN 连接测试
- **`test_peer_offer`** - 完整的端到端连接和音频回声测试
- **`test_dtls`** - DTLS-SRTP 安全层测试

### 音频回声测试
`test_peer_offer` 应用程序演示了：
- 随机 SSRC 生成
- 音频数据包生成和验证
- 实时音频流和回声验证
- 连接状态监控

```bash
# 运行音频回声测试 (发送 1000 个数据包，间隔 20ms)
./build/tests/test_peer_offer
```

## 📱 平台示例

平台特定的示例目前正在更新以使用新的 C++ 接口。请稍后查看：
- **树莓派** - 完整的视频和双向音频流
- **ESP32** - 通过数据通道进行 MJPEG 流传输  
- **树莓派 Pico** - 轻量级数据通道消息传递

目前请参考 `tests/` 目录中的测试应用程序了解使用示例。

## 🔧 配置选项

### 构建选项
```bash
# 带详细日志的调试构建
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug

# 针对大小优化的发布构建
cmake -S . -B build -DCMAKE_BUILD_TYPE=MinSizeRel

# 禁用数据通道支持
cmake -S . -B build -DCONFIG_ENABLE_DATACHANNEL=OFF
```

### 运行时配置
`include/config.h` 中的关键配置选项：
- `CONFIG_MTU` - 最大传输单元 (默认: 1500)
- `CONFIG_KEEPALIVE_TIMEOUT` - 连接超时 (默认: 10000ms)
- `CONFIG_ENABLE_DATACHANNEL` - 数据通道支持开关

## 🔒 安全特性

- **DTLS 1.2** 媒体流加密
- **SRTP** 实时媒体保护  
- **证书指纹验证** 对等端验证
- **安全随机** SSRC 生成
- **内存安全** C++ 实现

## 🤝 贡献指南

欢迎贡献！请确保：
1. 代码遵循现有的 C++ 风格
2. 新功能包含适当的测试
3. 为 API 更改更新文档
4. 提交 PR 前所有测试通过

## 🙏 致谢

本项目基于由 @sepfy 创建的优秀 [libpeer](https://github.com/sepfy/libpeer) 项目。原始 libpeer 提供了：

- 基于 C 实现的稳固 WebRTC 基础
- 全面的平台支持 (ESP32、树莓派、Pico)
- 精心设计的网络和媒体处理架构
- 全面的测试框架和示例

我们的现代化工作重点是：
- 重构为现代 C++ (C++17)
- 通过 RAII 和智能指针提高内存安全
- 使用用户管理的信令简化 API
- 针对嵌入式应用优化性能

我们深深感谢原始贡献者的出色工作，正是他们让这个项目成为可能。

## 📄 许可证

本项目按照 LICENSE 文件中指定的条款进行许可。

## 🆘 支持

- **问题反馈**: [GitHub Issues](https://github.com/wanghengwen/webrtc-iot/issues)
- **文档**: 参见内联代码注释和测试应用程序
- **示例**: `tests/` 目录中的测试应用程序演示了库的使用方法

---