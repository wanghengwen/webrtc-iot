#ifndef DTLS_SRTP_HPP_
#define DTLS_SRTP_HPP_

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <memory>
#include <string>
#include <functional>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/timing.h>
#include <mbedtls/x509_crt.h>

#include "config.h"
#include "address.h"
#if CONFIG_ENABLE_RTP_ENCRYPTION
#if ESP_PLATFORM
#include <srtp.h>
#else
#include <srtp2/srtp.h>
#endif
#endif

namespace rtc {

#if CONFIG_ENABLE_RTP_ENCRYPTION
#define SRTP_MASTER_KEY_LENGTH 16
#define SRTP_MASTER_SALT_LENGTH 14
#define DTLS_SRTP_KEY_MATERIAL_LENGTH 60
#endif
#define DTLS_SRTP_FINGERPRINT_LENGTH 160

enum class DtlsSrtpRole {
    CLIENT,
    SERVER
};

enum class DtlsSrtpState {
    INIT,
    HANDSHAKE,
    CONNECTED
};

using UdpSendCallback = std::function<int(const uint8_t* buf, size_t len)>;
using UdpRecvCallback = std::function<int(uint8_t* buf, size_t len)>;

class DtlsSrtpSession {
public:
    DtlsSrtpSession();
    ~DtlsSrtpSession();
    
    // Copy and move operations
    DtlsSrtpSession(const DtlsSrtpSession&) = delete;
    DtlsSrtpSession& operator=(const DtlsSrtpSession&) = delete;
    DtlsSrtpSession(DtlsSrtpSession&&) = default;
    DtlsSrtpSession& operator=(DtlsSrtpSession&&) = default;
    
    // Library initialization (call once per process)
    static void init_srtp_library();
    static void deinit_srtp_library();
    
    // Initialization and cleanup
    int init(DtlsSrtpRole role, void* user_data);
    void deinit();
    
    // Certificate management
    int create_cert();
    
    // Session management
    int handshake(Address* addr);
    void reset_session();
    
    // Data transmission
    int write(const uint8_t* buf, size_t len);
    int read(uint8_t* buf, size_t len);
    
    // SCTP to DTLS conversion
    void sctp_to_dtls(uint8_t* packet, int bytes);
    
    // Packet probing
    static bool probe(const uint8_t* buf);
    
    // SRTP encryption/decryption
#if CONFIG_ENABLE_RTP_ENCRYPTION
    void decrypt_rtp_packet(uint8_t* packet, int* bytes);
    void decrypt_rtcp_packet(uint8_t* packet, int* bytes);
    void encrypt_rtp_packet(uint8_t* packet, int* bytes);
    void encrypt_rtcp_packet(uint8_t* packet, int* bytes);
#endif
    
    // Getters
    DtlsSrtpState get_state() const { return state_; }
    DtlsSrtpRole get_role() const { return role_; }
    const std::string& get_local_fingerprint() const { return local_fingerprint_; }
    const std::string& get_remote_fingerprint() const { return remote_fingerprint_; }
    
    // Setters
    void set_remote_fingerprint(const std::string& fingerprint) { remote_fingerprint_ = fingerprint; }
    void set_udp_callbacks(UdpSendCallback send_cb, UdpRecvCallback recv_cb);
    
    // Key derivation (public for callback access)
#if CONFIG_ENABLE_RTP_ENCRYPTION
    int extract_srtp_keys(const unsigned char* master_secret, size_t secret_len,
                         const unsigned char* randbytes, size_t randbytes_len,
                         mbedtls_tls_prf_types tls_prf_type);
#endif

private:
    // MbedTLS context
    mbedtls_ssl_context ssl_;
    mbedtls_ssl_config conf_;
    mbedtls_ssl_cookie_ctx cookie_ctx_;
    mbedtls_x509_crt cert_;
    mbedtls_pk_context pkey_;
    mbedtls_entropy_context entropy_;
    mbedtls_ctr_drbg_context ctr_drbg_;

    // SRTP policies and contexts
#if CONFIG_ENABLE_RTP_ENCRYPTION
    srtp_policy_t remote_policy_;
    srtp_policy_t local_policy_;
    srtp_t srtp_in_;
    srtp_t srtp_out_;
    uint8_t remote_policy_key_[SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH];
    uint8_t local_policy_key_[SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH];
#endif

    // Network callbacks
    UdpSendCallback udp_send_;
    UdpRecvCallback udp_recv_;

    Address* remote_addr_;
    DtlsSrtpRole role_;
    DtlsSrtpState state_;

    std::string local_fingerprint_;
    std::string remote_fingerprint_;
    std::string actual_remote_fingerprint_;

    void* user_data_;

    // Helper methods
    void x509_digest(const mbedtls_x509_crt* crt, std::string& fingerprint);
    int selfsign_cert();
    
    // Static callbacks for mbedTLS
    static int udp_send_wrapper(void* ctx, const uint8_t* buf, size_t len);
    static int udp_recv_wrapper(void* ctx, uint8_t* buf, size_t len);
    static int cert_verify_wrapper(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags);
    
    void setup_srtp_policies();
    int do_handshake();
    int handshake_server();
    int handshake_client();
};

} // namespace rtc

#endif  // DTLS_SRTP_HPP_