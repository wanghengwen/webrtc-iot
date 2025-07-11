#ifndef CONFIG_H_
#define CONFIG_H_

// uncomment this if you want to handshake with a aiortc
// #define CONFIG_DTLS_USE_ECDSA 1

#define SCTP_MTU (1200)
#define CONFIG_MTU (1300)

#ifndef CONFIG_USE_LWIP
#define CONFIG_USE_LWIP 0
#endif

#ifndef CONFIG_MBEDTLS_DEBUG
#define CONFIG_MBEDTLS_DEBUG 0
#endif

#ifndef CONFIG_MBEDTLS_2_X
#define CONFIG_MBEDTLS_2_X 0
#endif

#if CONFIG_MBEDTLS_2_X
#define RSA_KEY_LENGTH 512
#else
#define RSA_KEY_LENGTH 1024
#endif

#ifndef CONFIG_DTLS_USE_ECDSA
#define CONFIG_DTLS_USE_ECDSA 0
#endif

#ifndef CONFIG_USE_USRSCTP
#define CONFIG_USE_USRSCTP 1
#endif

#ifndef CONFIG_ENABLE_DATACHANNEL
#define CONFIG_ENABLE_DATACHANNEL 1
#endif

#ifndef CONFIG_ENABLE_RTP_ENCRYPTION
#define CONFIG_ENABLE_RTP_ENCRYPTION 1
#endif

#ifndef CONFIG_SDP_BUFFER_SIZE
#define CONFIG_SDP_BUFFER_SIZE 2048
#endif

#ifndef CONFIG_TLS_READ_TIMEOUT
#define CONFIG_TLS_READ_TIMEOUT 3000
#endif

#ifndef CONFIG_KEEPALIVE_TIMEOUT
#define CONFIG_KEEPALIVE_TIMEOUT 30000
#endif

#ifndef CONFIG_AUDIO_DURATION
#define CONFIG_AUDIO_DURATION 20
#endif

#ifndef CONFIG_MAX_NALU_SIZE
#define CONFIG_MAX_NALU_SIZE (10 * 1024)  // 10KB
#endif

#define CONFIG_IPV6 0
// empty will use first active interface
#define CONFIG_IFACE_PREFIX ""

// #define LOG_LEVEL LEVEL_DEBUG
#define LOG_REDIRECT 0


#endif  // CONFIG_H_
