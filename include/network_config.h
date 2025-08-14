#ifndef NETWORK_CONFIG_H_
#define NETWORK_CONFIG_H_

// ESP32-S3 网络优化配置
// 解决 "Not enough space" 错误的配置建议

#ifdef CONFIG_IDF_TARGET_ESP32S3

// UDP 缓冲区配置
#define UDP_SEND_BUFFER_SIZE    (16 * 1024)  // 16KB 发送缓冲区
#define UDP_RECV_BUFFER_SIZE    (16 * 1024)  // 16KB 接收缓冲区

// WebRTC 相关配置
#define WEBRTC_MAX_PACKET_SIZE  1500         // MTU 大小
#define WEBRTC_PACKET_QUEUE_SIZE 64          // 数据包队列大小

// LWIP 优化建议（需要在 menuconfig 中配置）
// CONFIG_LWIP_MAX_UDP_PCBS=512           // 最大 UDP PCB 数量
// CONFIG_LWIP_UDP_RECVMBOX_SIZE=32       // UDP 接收邮箱大小（当前为6，建议增加）
// CONFIG_LWIP_TCPIP_RECVMBOX_SIZE=64     // TCPIP 接收邮箱大小（当前为32）
// CONFIG_LWIP_MAX_SOCKETS=32             // 最大 socket 数量（当前为16）

// ESP32 内存池配置建议
// CONFIG_ESP32_WIFI_STATIC_RX_BUFFER_NUM=16   // WiFi 静态接收缓冲区数量
// CONFIG_ESP32_WIFI_DYNAMIC_RX_BUFFER_NUM=32  // WiFi 动态接收缓冲区数量
// CONFIG_ESP32_WIFI_DYNAMIC_TX_BUFFER_NUM=32  // WiFi 动态发送缓冲区数量

// 内存诊断宏
#define NETWORK_DEBUG_MEMORY    1  // 启用内存调试信息

// 错误重试配置
#define UDP_SEND_RETRY_COUNT    3  // 发送失败重试次数
#define UDP_SEND_RETRY_DELAY_MS 10 // 重试延迟（毫秒）

#endif // CONFIG_IDF_TARGET_ESP32S3

// 通用网络调试宏
#ifdef NETWORK_DEBUG_MEMORY
#include "esp_heap_caps.h"
#define PRINT_HEAP_INFO() do { \
    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_DEFAULT); \
    size_t min_free_heap = heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT); \
    size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT); \
    printf("Heap Info - Free: %u, Min Free: %u, Largest Block: %u\n", \
           (unsigned)free_heap, (unsigned)min_free_heap, (unsigned)largest_block); \
} while(0)
#else
#define PRINT_HEAP_INFO()
#endif

#endif // NETWORK_CONFIG_H_