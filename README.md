# webrtc-iot - Modern C++ WebRTC Library for IoT/Embedded Devices

![build](https://github.com/wanghengwen/webrtc-iot/actions/workflows/build.yml/badge.svg)

webrtc-iot is a modern WebRTC implementation written in C++, designed for IoT and embedded device streaming applications. The library has been extensively refactored to provide a clean C++ interface while maintaining performance and portability for resource-constrained environments.

> **Acknowledgments**: This project is based on the excellent work of [libpeer](https://github.com/sepfy/libpeer) by @sepfy. We extend our sincere gratitude for providing the foundational WebRTC implementation that made this C++ modernization possible.

## ✨ Key Features

### Media Support
- **Video Codecs**
  - H.264 with fragmentation support
  - Configurable frame rates and bitrates
- **Audio Codecs**  
  - G.711 PCM (A-law/µ-law)
  - OPUS with configurable bitrates
- **Real-time Processing**
  - Optimized RTP/RTCP handling
  - Dynamic SSRC generation

### WebRTC Core Features
- **Peer-to-Peer Connectivity**
  - ICE (Interactive Connectivity Establishment)
  - STUN/TURN server support
  - IPv4/IPv6 dual-stack
- **Security**
  - DTLS-SRTP encryption
  - Certificate fingerprint validation
  - Secure key exchange
- **Data Channels**
  - SCTP-based reliable/unreliable messaging
  - Binary and text data support
  - Multiple channels per connection


## 🏗️ Architecture

### Modern C++ Design
- **RAII** resource management
- **Smart pointers** for memory safety
- **std::function** callbacks for flexible event handling
- **Namespace organization** (`rtc::` namespace)
- **Exception-safe** operations

### Project Structure
```
webrtc-iot/
├── include/           # Public headers (C++ and C)
├── src/              # Implementation files
├── tests/            # Test applications
└── third_party/      # External dependencies
```

### Key Classes
- `rtc::PeerConnection` - Main WebRTC peer connection
- `rtc::IceAgent` - ICE connectivity management  
- `rtc::RtpEncoder/RtpDecoder` - Media processing
- `rtc::DtlsSrtpSession` - Security layer
- `rtc::SctpAssociation` - Data channel support

## 📦 Dependencies

| Library | Purpose | Version |
|---------|---------|---------|
| [mbedTLS](https://github.com/Mbed-TLS/mbedtls) | Cryptography & TLS | Latest |
| [libsrtp](https://github.com/cisco/libsrtp) | SRTP encryption | v2.x |
| [usrsctp](https://github.com/sctplab/usrsctp) | SCTP for data channels | Latest |

All dependencies are automatically downloaded and built via CMake.

## 🚀 Quick Start

### Prerequisites
```bash
sudo apt update && sudo apt install -y git cmake build-essential
```

### Build and Test
```bash
# Clone with all submodules
git clone --recursive https://github.com/wanghengwen/webrtc-iot
cd webrtc-iot

# Build the library and tests
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Run basic connectivity test
./build/tests/test_agent

# Test peer connection with audio echo
./build/tests/test_peer_offer
```

### Basic Usage Example

```cpp
#include "peer_connection.hpp"

int main() {
    // Configure the peer connection
    rtc::PeerConfiguration config;
    config.audio_codec = rtc::MediaCodec::PCMU;
    
    // Add STUN server for NAT traversal
    config.ice_servers.push_back({
        .urls = "stun:stun.l.google.com:19302"
    });
    
    // Create peer connection
    rtc::PeerConnection pc(config);
    
    // Set up callbacks
    pc.on_ice_connection_state_change([](rtc::PeerConnectionState state) {
        std::cout << "Connection state: " << static_cast<int>(state) << std::endl;
    });
    
    // Create and handle offer/answer
    std::string offer = pc.create_offer();
    std::cout << "Local offer: " << offer << std::endl;
    
    return 0;
}
```

## 🧪 Testing Applications

The project includes several test applications demonstrating different features:

### Core Tests
- **`test_agent`** - ICE agent and STUN connectivity testing
- **`test_peer_offer`** - Complete peer connection with audio echo test
- **`test_dtls`** - DTLS-SRTP security layer testing

### Audio Echo Test
The `test_peer_offer` application demonstrates:
- Random SSRC generation
- Audio packet generation and validation
- Real-time audio streaming with echo verification
- Connection state monitoring

```bash
# Run audio echo test (sends 1000 packets, 20ms intervals)
./build/tests/test_peer_offer
```

## 📱 Platform Examples

Platform-specific examples are currently being updated to use the new C++ interface. Please check back soon for:
- **Raspberry Pi** - Full video and bidirectional audio streaming
- **ESP32** - MJPEG streaming over data channels  
- **Raspberry Pi Pico** - Lightweight data channel messaging

For now, please refer to the test applications in `tests/` directory for usage examples.

## 🔧 Configuration

### Build Options
```bash
# Debug build with verbose logging
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug

# Release build optimized for size
cmake -S . -B build -DCMAKE_BUILD_TYPE=MinSizeRel

# Disable data channel support
cmake -S . -B build -DCONFIG_ENABLE_DATACHANNEL=OFF
```

### Runtime Configuration
Key configuration options in `include/config.h`:
- `CONFIG_MTU` - Maximum transmission unit (default: 1500)
- `CONFIG_KEEPALIVE_TIMEOUT` - Connection timeout (default: 10000ms)
- `CONFIG_ENABLE_DATACHANNEL` - Data channel support toggle

## 🔒 Security Features

- **DTLS 1.2** encryption for media streams
- **SRTP** for real-time media protection  
- **Certificate fingerprinting** for peer verification
- **Secure random** SSRC generation
- **Memory-safe** C++ implementation

## 🤝 Contributing

Contributions are welcome! Please ensure:
1. Code follows the existing C++ style
2. New features include appropriate tests
3. Documentation is updated for API changes
4. All tests pass before submitting PRs

## 🙏 Acknowledgments

This project builds upon the outstanding work of the [libpeer](https://github.com/sepfy/libpeer) project created by @sepfy. The original libpeer provided:

- Solid WebRTC foundation with C implementation
- Comprehensive platform support (ESP32, Raspberry Pi, Pico)
- Well-designed networking and media processing architecture
- Extensive testing framework and examples

Our modernization efforts focused on:
- Refactoring to modern C++ (C++17)
- Improving memory safety with RAII and smart pointers
- Simplifying the API with user-managed signaling
- Optimizing performance for embedded applications

We are deeply grateful to the original contributors for their excellent work that made this project possible.

## 📄 License

This project is licensed under the terms specified in the LICENSE file.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/wanghengwen/webrtc-iot/issues)
- **Documentation**: See inline code comments and test applications
- **Examples**: Test applications in `tests/` directory demonstrate library usage

---
