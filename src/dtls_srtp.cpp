#include "dtls_srtp.hpp"

#include <cstring>
#include <memory>

#include "config.h"
#include "ports.h"
#include "socket.h"
#include "utils.h"
#include <srtp2/srtp.h>

#if CONFIG_MBEDTLS_DEBUG
#include "mbedtls/debug.h"
#endif
#include "mbedtls/sha256.h"


namespace rtc {

namespace {
    bool srtp_library_initialized = false;
}

void DtlsSrtpSession::init_srtp_library() {
    if (!srtp_library_initialized) {
        if (srtp_init() != srtp_err_status_ok) {
            LOGE("libsrtp init failed");
        } else {
            srtp_library_initialized = true;
        }
    }
}

void DtlsSrtpSession::deinit_srtp_library() {
    if (srtp_library_initialized) {
        srtp_shutdown();
        srtp_library_initialized = false;
    }
}

DtlsSrtpSession::DtlsSrtpSession() 
    : remote_addr_(nullptr)
    , role_(DtlsSrtpRole::CLIENT)
    , state_(DtlsSrtpState::INIT)
    , user_data_(nullptr) {
    
    // Initialize mbedTLS contexts
    mbedtls_ssl_init(&ssl_);
    mbedtls_ssl_config_init(&conf_);
    mbedtls_x509_crt_init(&cert_);
    mbedtls_pk_init(&pkey_);
    mbedtls_entropy_init(&entropy_);
    mbedtls_ctr_drbg_init(&ctr_drbg_);
    mbedtls_ssl_cookie_init(&cookie_ctx_);
    
    // Initialize SRTP contexts
    memset(&remote_policy_, 0, sizeof(remote_policy_));
    memset(&local_policy_, 0, sizeof(local_policy_));
    memset(remote_policy_key_, 0, sizeof(remote_policy_key_));
    memset(local_policy_key_, 0, sizeof(local_policy_key_));
    srtp_in_ = nullptr;
    srtp_out_ = nullptr;
}

DtlsSrtpSession::~DtlsSrtpSession() {
    deinit();
}

void DtlsSrtpSession::deinit() {
    // Free mbedTLS contexts
    mbedtls_ssl_free(&ssl_);
    mbedtls_ssl_config_free(&conf_);
    mbedtls_x509_crt_free(&cert_);
    mbedtls_pk_free(&pkey_);
    mbedtls_entropy_free(&entropy_);
    mbedtls_ctr_drbg_free(&ctr_drbg_);
    
    if (role_ == DtlsSrtpRole::SERVER) {
        mbedtls_ssl_cookie_free(&cookie_ctx_);
    }
    
    // Free SRTP contexts
    if (state_ == DtlsSrtpState::CONNECTED) {
        if (srtp_in_) {
            srtp_dealloc(srtp_in_);
            srtp_in_ = nullptr;
        }
        if (srtp_out_) {
            srtp_dealloc(srtp_out_);
            srtp_out_ = nullptr;
        }
    }
}

int DtlsSrtpSession::udp_send_wrapper(void* ctx, const uint8_t* buf, size_t len) {
    DtlsSrtpSession* session = static_cast<DtlsSrtpSession*>(ctx);
    if (session->udp_send_) {
        int ret = session->udp_send_(buf, len);
        LOGI("DTLS UDP send via callback: %d bytes, result: %d", static_cast<int>(len), ret);
        return ret;
    }
    
    // Fallback to default UDP socket send
    UdpSocket* udp_socket = static_cast<UdpSocket*>(session->user_data_);
    if (udp_socket && session->remote_addr_) {
        int ret = udp_socket_sendto(udp_socket, session->remote_addr_, buf, len);
        LOGI("DTLS UDP send via socket: %d bytes, result: %d", static_cast<int>(len), ret);
        return ret;
    }
    
    LOGE("DTLS UDP send failed: no callback or socket available");
    return -1;
}

int DtlsSrtpSession::udp_recv_wrapper(void* ctx, uint8_t* buf, size_t len) {
    DtlsSrtpSession* session = static_cast<DtlsSrtpSession*>(ctx);
    if (session->udp_recv_) {
        // For DTLS handshake, we need blocking behavior like original C version
        int ret;
        int attempts = 0;
        const int max_attempts = 100; // Max 100ms wait
        
        do {
            ret = session->udp_recv_(buf, len);
            if (ret > 0) {
                LOGI("DTLS UDP recv via callback: %d bytes (attempt %d)", ret, attempts + 1);
                return ret;
            } else if (ret == 0) {
                // Timeout - wait a bit and retry like original C version
                ports_sleep_ms(1);
                attempts++;
            } else {
                LOGD("DTLS UDP recv via callback: error %d", ret);
                return ret;
            }
        } while (attempts < max_attempts);
        
        LOGD("DTLS UDP recv timeout after %d attempts", attempts);
        return ret;
    }
    
    // Fallback to default UDP socket recv
    UdpSocket* udp_socket = static_cast<UdpSocket*>(session->user_data_);
    if (udp_socket) {
        int ret;
        while ((ret = udp_socket_recvfrom(udp_socket, &udp_socket->bind_addr, buf, len)) <= 0) {
            ports_sleep_ms(1);
        }
        LOGI("DTLS UDP recv via socket: %d bytes", ret);
        return ret;
    }
    
    LOGE("DTLS UDP recv failed: no callback or socket available");
    return -1;
}

int DtlsSrtpSession::cert_verify_wrapper(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    // Do not verify CA - accept all certificates
    *flags &= ~(MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_CN_MISMATCH | MBEDTLS_X509_BADCERT_BAD_KEY);
    return 0;
}

void DtlsSrtpSession::x509_digest(const mbedtls_x509_crt* crt, std::string& fingerprint) {
    unsigned char digest[32];
    char hex_buffer[4];
    
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, crt->raw.p, crt->raw.len);
    mbedtls_sha256_finish(&sha256_ctx, digest);
    mbedtls_sha256_free(&sha256_ctx);
    
    fingerprint.clear();
    fingerprint.reserve(96); // 32 * 3 = 96 characters (hex + colons)
    
    for (int i = 0; i < 32; i++) {
        snprintf(hex_buffer, sizeof(hex_buffer), "%.2X:", digest[i]);
        fingerprint.append(hex_buffer);
    }
    
    // Remove the last colon
    if (!fingerprint.empty()) {
        fingerprint.pop_back();
    }
}

int DtlsSrtpSession::selfsign_cert() {
    int ret;
    mbedtls_x509write_cert crt;
    std::unique_ptr<unsigned char[]> cert_buf(new unsigned char[RSA_KEY_LENGTH * 2]);
    
#if CONFIG_MBEDTLS_2_X
    mbedtls_mpi serial;
#else
    const char* serial = "peer";
#endif
    const char* pers = "dtls_srtp";
    
    // Seed the random number generator
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_, 
                                reinterpret_cast<const unsigned char*>(pers), strlen(pers));
    if (ret != 0) {
        LOGE("mbedtls_ctr_drbg_seed failed -0x%.4x", static_cast<unsigned int>(-ret));
        return ret;
    }
    
    // Generate key pair
#if CONFIG_DTLS_USE_ECDSA
    ret = mbedtls_pk_setup(&pkey_, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) {
        LOGE("mbedtls_pk_setup failed -0x%.4x", static_cast<unsigned int>(-ret));
        return ret;
    }
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pkey_), 
                             mbedtls_ctr_drbg_random, &ctr_drbg_);
#else
    ret = mbedtls_pk_setup(&pkey_, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) {
        LOGE("mbedtls_pk_setup failed -0x%.4x", static_cast<unsigned int>(-ret));
        return ret;
    }
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pkey_), mbedtls_ctr_drbg_random, &ctr_drbg_, 
                             RSA_KEY_LENGTH, 65537);
#endif
    
    if (ret != 0) {
        LOGE("Key generation failed -0x%.4x", static_cast<unsigned int>(-ret));
        return ret;
    }
    
    // Initialize certificate writing context
    mbedtls_x509write_crt_init(&crt);
    
    // Set certificate parameters
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &pkey_);
    mbedtls_x509write_crt_set_issuer_key(&crt, &pkey_);
    
    ret = mbedtls_x509write_crt_set_subject_name(&crt, "CN=dtls_srtp");
    if (ret != 0) {
        LOGE("mbedtls_x509write_crt_set_subject_name failed -0x%.4x", static_cast<unsigned int>(-ret));
        mbedtls_x509write_crt_free(&crt);
        return ret;
    }
    
    ret = mbedtls_x509write_crt_set_issuer_name(&crt, "CN=dtls_srtp");
    if (ret != 0) {
        LOGE("mbedtls_x509write_crt_set_issuer_name failed -0x%.4x", static_cast<unsigned int>(-ret));
        mbedtls_x509write_crt_free(&crt);
        return ret;
    }
    
    // Set serial number
#if CONFIG_MBEDTLS_2_X
    mbedtls_mpi_init(&serial);
    ret = mbedtls_mpi_fill_random(&serial, 16, mbedtls_ctr_drbg_random, &ctr_drbg_);
    if (ret != 0) {
        LOGE("mbedtls_mpi_fill_random failed -0x%.4x", static_cast<unsigned int>(-ret));
        mbedtls_mpi_free(&serial);
        mbedtls_x509write_crt_free(&crt);
        return ret;
    }
    ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
    mbedtls_mpi_free(&serial);
#else
    ret = mbedtls_x509write_crt_set_serial_raw(&crt, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(serial)), strlen(serial));
#endif
    
    if (ret != 0) {
        LOGE("mbedtls_x509write_crt_set_serial failed -0x%.4x", static_cast<unsigned int>(-ret));
        mbedtls_x509write_crt_free(&crt);
        return ret;
    }
    
    // Set validity period
    ret = mbedtls_x509write_crt_set_validity(&crt, "20180101000000", "20280101000000");
    if (ret != 0) {
        LOGE("mbedtls_x509write_crt_set_validity failed -0x%.4x", static_cast<unsigned int>(-ret));
        mbedtls_x509write_crt_free(&crt);
        return ret;
    }
    
    // Write certificate to PEM format
    ret = mbedtls_x509write_crt_pem(&crt, cert_buf.get(), 2 * RSA_KEY_LENGTH, 
                                   mbedtls_ctr_drbg_random, &ctr_drbg_);
    if (ret < 0) {
        LOGE("mbedtls_x509write_crt_pem failed -0x%.4x", static_cast<unsigned int>(-ret));
        mbedtls_x509write_crt_free(&crt);
        return ret;
    }
    
    // Parse the certificate
    ret = mbedtls_x509_crt_parse(&cert_, cert_buf.get(), 2 * RSA_KEY_LENGTH);
    if (ret != 0) {
        LOGE("mbedtls_x509_crt_parse failed -0x%.4x", static_cast<unsigned int>(-ret));
        mbedtls_x509write_crt_free(&crt);
        return ret;
    }
    
    mbedtls_x509write_crt_free(&crt);
    return 0;
}

#if CONFIG_MBEDTLS_DEBUG
static void debug_callback(void* ctx, int level, const char* file, int line, const char* str) {
    LOGD("%s:%04d: %s", file, line, str);
}
#endif

int DtlsSrtpSession::init(DtlsSrtpRole role, void* user_data) {
    static const mbedtls_ssl_srtp_profile default_profiles[] = {
        MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80,
        MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32,
        MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80,
        MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32,
        MBEDTLS_TLS_SRTP_UNSET
    };
    
    role_ = role;
    state_ = DtlsSrtpState::INIT;
    user_data_ = user_data;
    
    // Initialize debug logging if enabled
#if CONFIG_MBEDTLS_DEBUG
    mbedtls_debug_set_threshold(3);
    mbedtls_ssl_conf_dbg(&conf_, debug_callback, nullptr);
#endif
    
    // Create self-signed certificate
    int ret = selfsign_cert();
    if (ret != 0) {
        LOGE("selfsign_cert failed -0x%.4x", static_cast<unsigned int>(-ret));
        return ret;
    }
    
    // Configure for client or server FIRST (exactly like original C version)
    if (role_ == DtlsSrtpRole::SERVER) {
        ret = mbedtls_ssl_config_defaults(&conf_,
                                         MBEDTLS_SSL_IS_SERVER,
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0) {
            LOGE("mbedtls_ssl_config_defaults (server) failed -0x%.4x", static_cast<unsigned int>(-ret));
            return ret;
        }
        
        ret = mbedtls_ssl_cookie_setup(&cookie_ctx_, mbedtls_ctr_drbg_random, &ctr_drbg_);
        if (ret != 0) {
            LOGE("mbedtls_ssl_cookie_setup failed -0x%.4x", static_cast<unsigned int>(-ret));
            return ret;
        }
        
        mbedtls_ssl_conf_dtls_cookies(&conf_, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &cookie_ctx_);
    } else {
        ret = mbedtls_ssl_config_defaults(&conf_,
                                         MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0) {
            LOGE("mbedtls_ssl_config_defaults (client) failed -0x%.4x", static_cast<unsigned int>(-ret));
            return ret;
        }
    }
    
    // THEN configure SSL context AFTER defaults (exactly like original C version)
    mbedtls_ssl_conf_verify(&conf_, cert_verify_wrapper, nullptr);
    mbedtls_ssl_conf_authmode(&conf_, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf_, &cert_, nullptr);
    mbedtls_ssl_conf_own_cert(&conf_, &cert_, &pkey_);
    mbedtls_ssl_conf_rng(&conf_, mbedtls_ctr_drbg_random, &ctr_drbg_);
    mbedtls_ssl_conf_read_timeout(&conf_, 1000);
    
    // Generate local fingerprint
    x509_digest(&cert_, local_fingerprint_);
    LOGD("local fingerprint: %s", local_fingerprint_.c_str());
    
    // Configure DTLS-SRTP
    mbedtls_ssl_conf_dtls_srtp_protection_profiles(&conf_, default_profiles);
    mbedtls_ssl_conf_srtp_mki_value_supported(&conf_, MBEDTLS_SSL_DTLS_SRTP_MKI_UNSUPPORTED);
    mbedtls_ssl_conf_cert_req_ca_list(&conf_, MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED);
    
    // Setup SSL context
    ret = mbedtls_ssl_setup(&ssl_, &conf_);
    if (ret != 0) {
        LOGE("mbedtls_ssl_setup failed -0x%.4x", static_cast<unsigned int>(-ret));
        return ret;
    }
    
    return 0;
}

void DtlsSrtpSession::set_udp_callbacks(UdpSendCallback send_cb, UdpRecvCallback recv_cb) {
    udp_send_ = std::move(send_cb);
    udp_recv_ = std::move(recv_cb);
}

#if CONFIG_MBEDTLS_2_X
static int key_derivation_callback(void* context,
                                  const unsigned char* ms,
                                  const unsigned char* kb,
                                  size_t maclen,
                                  size_t keylen,
                                  size_t ivlen,
                                  const unsigned char client_random[32],
                                  const unsigned char server_random[32],
                                  mbedtls_tls_prf_types tls_prf_type) {
#else
static void key_derivation_callback(void* context,
                                   mbedtls_ssl_key_export_type secret_type,
                                   const unsigned char* secret,
                                   size_t secret_len,
                                   const unsigned char client_random[32],
                                   const unsigned char server_random[32],
                                   mbedtls_tls_prf_types tls_prf_type) {
#endif
    DtlsSrtpSession* session = static_cast<DtlsSrtpSession*>(context);
    
    unsigned char master_secret[48];
    unsigned char randbytes[64];
    
    memcpy(randbytes, client_random, 32);
    memcpy(randbytes + 32, server_random, 32);
    
#if CONFIG_MBEDTLS_2_X
    memcpy(master_secret, ms, sizeof(master_secret));
    return session->extract_srtp_keys(master_secret, sizeof(master_secret), randbytes, sizeof(randbytes), tls_prf_type);
#else
    memcpy(master_secret, secret, sizeof(master_secret));
    session->extract_srtp_keys(master_secret, sizeof(master_secret), randbytes, sizeof(randbytes), tls_prf_type);
#endif
}

int DtlsSrtpSession::extract_srtp_keys(const unsigned char* master_secret, size_t secret_len,
                                      const unsigned char* randbytes, size_t randbytes_len,
                                      mbedtls_tls_prf_types tls_prf_type) {
    const char* dtls_srtp_label = "EXTRACTOR-dtls_srtp";
    uint8_t key_material[DTLS_SRTP_KEY_MATERIAL_LENGTH];
    
    // Export keying material
    int ret = mbedtls_ssl_tls_prf(tls_prf_type, master_secret, secret_len, dtls_srtp_label,
                                 randbytes, randbytes_len, key_material, sizeof(key_material));
    if (ret != 0) {
        LOGE("mbedtls_ssl_tls_prf failed(%d)", ret);
        return ret;
    }
    
    // Extract keys and salts
    const uint8_t* client_key = key_material;
    const uint8_t* server_key = client_key + SRTP_MASTER_KEY_LENGTH;
    const uint8_t* client_salt = server_key + SRTP_MASTER_KEY_LENGTH;
    const uint8_t* server_salt = client_salt + SRTP_MASTER_SALT_LENGTH;
    
    const uint8_t *local_key, *remote_key, *local_salt, *remote_salt;
    if (role_ == DtlsSrtpRole::SERVER) {
        local_key = server_key;
        local_salt = server_salt;
        remote_key = client_key;
        remote_salt = client_salt;
    } else {
        local_key = client_key;
        local_salt = client_salt;
        remote_key = server_key;
        remote_salt = server_salt;
    }
    
    // Setup inbound SRTP session
    memset(&remote_policy_, 0, sizeof(remote_policy_));
    srtp_crypto_policy_set_rtp_default(&remote_policy_.rtp);
    srtp_crypto_policy_set_rtcp_default(&remote_policy_.rtcp);
    
    memcpy(remote_policy_key_, remote_key, SRTP_MASTER_KEY_LENGTH);
    memcpy(remote_policy_key_ + SRTP_MASTER_KEY_LENGTH, remote_salt, SRTP_MASTER_SALT_LENGTH);
    
    remote_policy_.ssrc.type = ssrc_any_inbound;
    remote_policy_.key = remote_policy_key_;
    remote_policy_.next = nullptr;
    
    if (srtp_create(&srtp_in_, &remote_policy_) != srtp_err_status_ok) {
        LOGE("Error creating inbound SRTP session");
        return -1;
    }
    
    LOGI("Created inbound SRTP session");
    
    // Setup outbound SRTP session
    memset(&local_policy_, 0, sizeof(local_policy_));
    srtp_crypto_policy_set_rtp_default(&local_policy_.rtp);
    srtp_crypto_policy_set_rtcp_default(&local_policy_.rtcp);
    
    memcpy(local_policy_key_, local_key, SRTP_MASTER_KEY_LENGTH);
    memcpy(local_policy_key_ + SRTP_MASTER_KEY_LENGTH, local_salt, SRTP_MASTER_SALT_LENGTH);
    
    local_policy_.ssrc.type = ssrc_any_outbound;
    local_policy_.key = local_policy_key_;
    local_policy_.next = nullptr;
    
    if (srtp_create(&srtp_out_, &local_policy_) != srtp_err_status_ok) {
        LOGE("Error creating outbound SRTP session");
        return -1;
    }
    
    LOGI("Created outbound SRTP session");
    state_ = DtlsSrtpState::CONNECTED;
    return 0;
}

int DtlsSrtpSession::do_handshake() {
    static mbedtls_timing_delay_context timer;
    
    mbedtls_ssl_set_timer_cb(&ssl_, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
    
#if CONFIG_MBEDTLS_2_X
    mbedtls_ssl_conf_export_keys_ext_cb(&conf_, key_derivation_callback, this);
#else
    mbedtls_ssl_set_export_keys_cb(&ssl_, key_derivation_callback, this);
#endif
    
    mbedtls_ssl_set_bio(&ssl_, this, udp_send_wrapper, udp_recv_wrapper, nullptr);
    
    int ret;
    do {
        ret = mbedtls_ssl_handshake(&ssl_);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    
    return ret;
}

int DtlsSrtpSession::handshake_server() {
    int ret;
    int attempts = 0;
    const int max_attempts = 3;
    
    while (attempts < max_attempts) {
        unsigned char client_ip[] = "test";
        
        ret = mbedtls_ssl_session_reset(&ssl_);
        if (ret != 0) {
            LOGE("mbedtls_ssl_session_reset failed -0x%.4x", static_cast<unsigned int>(-ret));
            break;
        }
        
        mbedtls_ssl_set_client_transport_id(&ssl_, client_ip, sizeof(client_ip));
        
        ret = do_handshake();
        attempts++;
        
        if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
            LOGD("DTLS hello verification requested");
        } else if (ret != 0) {
            LOGE("failed! mbedtls_ssl_handshake returned -0x%.4x (attempt %d/%d)", static_cast<unsigned int>(-ret), attempts, max_attempts);
            if (attempts >= max_attempts) {
                break;
            }
        } else {
            break;
        }
    }
    
    LOGD("DTLS server handshake done (attempts: %d)", attempts);
    return ret;
}

int DtlsSrtpSession::handshake_client() {
    int ret = do_handshake();
    if (ret != 0) {
        LOGE("failed! mbedtls_ssl_handshake returned -0x%.4x", static_cast<unsigned int>(-ret));
    }
    
    LOGD("DTLS client handshake done");
    return ret;
}

int DtlsSrtpSession::handshake(Address* addr) {
    remote_addr_ = addr;
    
    int ret;
    if (role_ == DtlsSrtpRole::SERVER) {
        ret = handshake_server();
    } else {
        ret = handshake_client();
    }
    
    if (ret != 0) {
        return ret;
    }
    
    // Verify remote certificate fingerprint
    const mbedtls_x509_crt* remote_crt = mbedtls_ssl_get_peer_cert(&ssl_);
    if (remote_crt != nullptr) {
        x509_digest(remote_crt, actual_remote_fingerprint_);
        
        if (!remote_fingerprint_.empty() && 
            remote_fingerprint_ != actual_remote_fingerprint_) {
            LOGE("Actual and Expected Fingerprint mismatch: %s %s",
                 remote_fingerprint_.c_str(),
                 actual_remote_fingerprint_.c_str());
            return -1;
        }
    } else {
        LOGE("no remote fingerprint");
        return -1;
    }
    
    // Get DTLS-SRTP negotiation result
    mbedtls_dtls_srtp_info dtls_srtp_negotiation_result;
    mbedtls_ssl_get_dtls_srtp_negotiation_result(&ssl_, &dtls_srtp_negotiation_result);
    
    return 0;
}

void DtlsSrtpSession::reset_session() {
    if (state_ == DtlsSrtpState::CONNECTED) {
        if (srtp_in_) {
            srtp_dealloc(srtp_in_);
            srtp_in_ = nullptr;
        }
        if (srtp_out_) {
            srtp_dealloc(srtp_out_);
            srtp_out_ = nullptr;
        }
        mbedtls_ssl_session_reset(&ssl_);
    }
    
    state_ = DtlsSrtpState::INIT;
}

int DtlsSrtpSession::write(const uint8_t* buf, size_t len) {
    int ret;
    do {
        ret = mbedtls_ssl_write(&ssl_, buf, len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    
    return ret;
}

int DtlsSrtpSession::read(uint8_t* buf, size_t len) {
    memset(buf, 0, len);
    
    int ret;
    do {
        ret = mbedtls_ssl_read(&ssl_, buf, len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    
    return ret;
}

void DtlsSrtpSession::sctp_to_dtls(uint8_t* packet, int bytes) {
    // This function would need to be implemented based on specific SCTP to DTLS conversion logic
    // The original C code doesn't have this function implemented either
    // This is a placeholder for future implementation
}

bool DtlsSrtpSession::probe(const uint8_t* buf) {
    if (buf == nullptr) {
        return false;
    }
    
    LOGD("DTLS content type: %d", buf[0]);
    // only handle application data
    return (buf[0] == 0x17);
}

void DtlsSrtpSession::decrypt_rtp_packet(uint8_t* packet, int* bytes) {
    if (srtp_in_) {
        srtp_unprotect(srtp_in_, packet, bytes);
    }
}

void DtlsSrtpSession::decrypt_rtcp_packet(uint8_t* packet, int* bytes) {
    if (srtp_in_) {
        srtp_unprotect_rtcp(srtp_in_, packet, bytes);
    }
}

void DtlsSrtpSession::encrypt_rtp_packet(uint8_t* packet, int* bytes) {
    if (srtp_out_) {
        srtp_protect(srtp_out_, packet, bytes);
    }
}

void DtlsSrtpSession::encrypt_rtcp_packet(uint8_t* packet, int* bytes) {
    if (srtp_out_) {
        srtp_protect_rtcp(srtp_out_, packet, bytes);
    }
}

int DtlsSrtpSession::create_cert() {
    return selfsign_cert();
}


} // namespace rtc
