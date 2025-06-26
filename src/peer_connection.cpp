#include "peer_connection.hpp"
#include <cstring>
#include <algorithm>
#include <random>
#include <chrono>

#include "ports.h"
#include "utils.h"
#include "sdp.hpp"

namespace rtc {

namespace {
    bool peer_library_initialized = false;
    
    // No need for codec conversion anymore - using C++ throughout
    
    uint32_t generate_random_ssrc() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<uint32_t> dis(1, 0xFFFFFFFF);
        return dis(gen);
    }
    
    void initialize_peer_library() {
        if (!peer_library_initialized) {
            rtc::DtlsSrtpSession::init_srtp_library();
#if CONFIG_ENABLE_DATACHANNEL && CONFIG_USE_USRSCTP
            rtc::SctpAssociation::init_usrsctp();
#endif
            peer_library_initialized = true;
        }
    }
    
    void deinitialize_peer_library() {
        if (peer_library_initialized) {
            rtc::DtlsSrtpSession::deinit_srtp_library();
#if CONFIG_ENABLE_DATACHANNEL && CONFIG_USE_USRSCTP
            rtc::SctpAssociation::deinit_usrsctp();
#endif
            peer_library_initialized = false;
        }
    }
}

PeerConnection::PeerConnection() 
    : state_(PeerConnectionState::NEW)
    , agent_ret_(-1)
    , local_description_created_(false)
    , dtls_handshake_delay_counter_(0)
    , remote_assrc_(0)
    , remote_vssrc_(0)
    , next_keepalive_time_(0)
    , time_of_last_activity_(0) {
    
    initialize_peer_library();
    
    // DTLS-SRTP session will be initialized when creating SDP
    
    // IceAgent uses RAII - no manual create needed
    agent_.create();
}

PeerConnection::PeerConnection(const PeerConfiguration& config) 
    : PeerConnection() {
    initialize_with_config(config);
}

PeerConnection::~PeerConnection() {
    cleanup();
}

PeerConnection::PeerConnection(PeerConnection&& other) noexcept 
    : config_(std::move(other.config_))
    , state_(other.state_)
    , agent_(std::move(other.agent_))
    , dtls_srtp_(std::move(other.dtls_srtp_))
#if CONFIG_ENABLE_DATACHANNEL
    , sctp_(std::move(other.sctp_))
#endif
    , sdp_(std::move(other.sdp_))
    , agent_ret_(other.agent_ret_)
    , local_description_created_(other.local_description_created_)
    , dtls_handshake_delay_counter_(other.dtls_handshake_delay_counter_)
    , artp_encoder_(std::move(other.artp_encoder_))
    , vrtp_encoder_(std::move(other.vrtp_encoder_))
    , vrtp_decoder_(std::move(other.vrtp_decoder_))
    , artp_decoder_(std::move(other.artp_decoder_))
    , remote_assrc_(other.remote_assrc_)
    , remote_vssrc_(other.remote_vssrc_)
    , next_keepalive_time_(other.next_keepalive_time_)
    , time_of_last_activity_(other.time_of_last_activity_)
    , on_ice_candidate_(std::move(other.on_ice_candidate_))
    , on_ice_connection_state_change_(std::move(other.on_ice_connection_state_change_))
    , on_receiver_packet_loss_(std::move(other.on_receiver_packet_loss_))
#if CONFIG_ENABLE_DATACHANNEL
    , on_datachannel_message_(std::move(other.on_datachannel_message_))
    , on_datachannel_open_(std::move(other.on_datachannel_open_))
    , on_datachannel_close_(std::move(other.on_datachannel_close_))
#endif
{
    // Clear the moved-from object to prevent double cleanup
    other.cleanup();
    // agent_ is moved, no need to clear
#if CONFIG_ENABLE_DATACHANNEL
    memset(&other.sctp_, 0, sizeof(other.sctp_));
#endif
}

PeerConnection& PeerConnection::operator=(PeerConnection&& other) noexcept {
    if (this != &other) {
        cleanup();
        
        config_ = std::move(other.config_);
        state_ = other.state_;
        agent_ = std::move(other.agent_);
        dtls_srtp_ = std::move(other.dtls_srtp_);
#if CONFIG_ENABLE_DATACHANNEL
        sctp_ = std::move(other.sctp_);
#endif
        sdp_ = std::move(other.sdp_);
        agent_ret_ = other.agent_ret_;
        local_description_created_ = other.local_description_created_;
        dtls_handshake_delay_counter_ = other.dtls_handshake_delay_counter_;
        artp_encoder_ = std::move(other.artp_encoder_);
        vrtp_encoder_ = std::move(other.vrtp_encoder_);
        vrtp_decoder_ = std::move(other.vrtp_decoder_);
        artp_decoder_ = std::move(other.artp_decoder_);
        remote_assrc_ = other.remote_assrc_;
        remote_vssrc_ = other.remote_vssrc_;
        next_keepalive_time_ = other.next_keepalive_time_;
        on_ice_candidate_ = std::move(other.on_ice_candidate_);
        on_ice_connection_state_change_ = std::move(other.on_ice_connection_state_change_);
        on_receiver_packet_loss_ = std::move(other.on_receiver_packet_loss_);
#if CONFIG_ENABLE_DATACHANNEL
        on_datachannel_message_ = std::move(other.on_datachannel_message_);
        on_datachannel_open_ = std::move(other.on_datachannel_open_);
        on_datachannel_close_ = std::move(other.on_datachannel_close_);
#endif
        
        // Clear the moved-from object to prevent double cleanup
        other.cleanup();
        // agent_ is moved, no need to clear
#if CONFIG_ENABLE_DATACHANNEL
        other.sctp_.reset();
#endif
        other.artp_encoder_.reset();
        other.vrtp_encoder_.reset();
        other.artp_decoder_.reset();
        other.vrtp_decoder_.reset();
    }
    return *this;
}

void PeerConnection::initialize_with_config(const PeerConfiguration& config) {
    config_ = config;
    
    // Initialize RTP encoders/decoders based on configuration
    if (config_.audio_codec != MediaCodec::NONE) {
        artp_encoder_ = std::make_unique<rtc::RtpEncoder>(config_.audio_codec, 
                           [this](const uint8_t* packet, size_t bytes) {
                               on_outgoing_rtp_packet(const_cast<uint8_t*>(packet), bytes, this);
                           });
        
        // Generate random SSRC for audio
        uint32_t audio_ssrc = generate_random_ssrc();
        artp_encoder_->set_ssrc(audio_ssrc);
        
        artp_decoder_ = std::make_unique<rtc::RtpDecoder>(config_.audio_codec,
                           [this](const uint8_t* data, size_t size) {
                               if (config_.on_audio_track) {
                                   config_.on_audio_track(data, size);
                               }
                           });
    }
    
    if (config_.video_codec != MediaCodec::NONE) {
        vrtp_encoder_ = std::make_unique<rtc::RtpEncoder>(config_.video_codec,
                           [this](const uint8_t* packet, size_t bytes) {
                               on_outgoing_rtp_packet(const_cast<uint8_t*>(packet), bytes, this);
                           });
        
        // Generate random SSRC for video
        uint32_t video_ssrc = generate_random_ssrc();
        vrtp_encoder_->set_ssrc(video_ssrc);
        
        vrtp_decoder_ = std::make_unique<rtc::RtpDecoder>(config_.video_codec,
                           [this](const uint8_t* data, size_t size) {
                               if (config_.on_video_track) {
                                   config_.on_video_track(data, size);
                               }
                           });
    }
}

void PeerConnection::cleanup() {
    if (state_ == PeerConnectionState::CLOSED) {
        return; // Already cleaned up or moved
    }
    
#if CONFIG_ENABLE_DATACHANNEL
    if (sctp_) {
        sctp_->destroy_association();
        sctp_.reset();
    }
#endif
    dtls_srtp_.deinit();
    agent_.destroy();
    
    // Reset RTP encoders/decoders
    artp_encoder_.reset();
    vrtp_encoder_.reset();
    artp_decoder_.reset();
    vrtp_decoder_.reset();
    
    state_ = PeerConnectionState::CLOSED;
}

void PeerConnection::close() {
    state_ = PeerConnectionState::CLOSED;
}

PeerConnectionState PeerConnection::get_state() const {
    return state_;
}

const std::string& PeerConnection::state_to_string() const {
    static const std::string states[] = {
        "closed", "new", "checking", "connected", "completed", "failed", "disconnected"
    };
    return states[static_cast<int>(state_)];
}

void PeerConnection::state_changed(PeerConnectionState new_state) {
    if (on_ice_connection_state_change_ && state_ != new_state) {
        // Reset keepalive timer when leaving COMPLETED state
        if (state_ == PeerConnectionState::COMPLETED && new_state != PeerConnectionState::COMPLETED) {
            next_keepalive_time_ = 0;
        }
        
        on_ice_connection_state_change_(new_state);
        state_ = new_state;
    }
}

int PeerConnection::Run() {
    uint32_t ssrc = 0;
    uint8_t recv_buf[CONFIG_MTU];

    for(int retryTries = 5; retryTries > 0; retryTries--) {
        agent_ret_ = -1;
        uint32_t current_time = ports_get_epoch_time();
        
        switch (state_) {
            case PeerConnectionState::NEW:
                retryTries = 0;
                break;
                
            case PeerConnectionState::CHECKING:
                if (agent_.select_candidate_pair() < 0) {
                    state_changed(PeerConnectionState::FAILED);
                } else if (agent_.connectivity_check() == 0) {
                    state_changed(PeerConnectionState::CONNECTED);
                }
                ports_sleep_ms(20);
                break;
                
            case PeerConnectionState::CONNECTED: {
                // Only attempt DTLS handshake if it hasn't completed yet
                if (dtls_srtp_.get_state() != rtc::DtlsSrtpState::CONNECTED) {
                    Address* remote_addr = agent_.get_nominated_remote_addr();
                    if (remote_addr) {
                        LOGI("DTLS handshake with remote addr (port: %d)", remote_addr->port);
                    } else {
                        LOGI("DTLS handshake with null remote addr");
                    }
                    
                    // Limit handshake attempts to prevent infinite loops
                    if (dtls_handshake_delay_counter_ < 30) {  // Increased attempts for better reliability
                        int handshake_result = dtls_srtp_.handshake(remote_addr);
                        dtls_handshake_delay_counter_++;
                        
                        if (handshake_result == 0) {
                            LOGI("DTLS-SRTP handshake done after %d attempts", dtls_handshake_delay_counter_);
                            
    #if CONFIG_ENABLE_DATACHANNEL
                            if (config_.datachannel != DataChannelType::NONE) {
                                LOGI("SCTP create socket");
                                sctp_ = std::make_unique<rtc::SctpAssociation>();
                                sctp_->create_association(&dtls_srtp_);
                            }
    #endif
                            state_changed(PeerConnectionState::COMPLETED);
                        } else if (handshake_result == -0x7280) {
                            // MBEDTLS_ERR_SSL_CONN_EOF - connection closed by peer
                            LOGD("DTLS handshake connection closed by peer (attempt %d/30)", dtls_handshake_delay_counter_);
                            // Add exponential backoff for retries
                            if (dtls_handshake_delay_counter_ < 10) {
                                ports_sleep_ms(20);
                            } else if (dtls_handshake_delay_counter_ < 20) {
                                ports_sleep_ms(50);
                            } else {
                                ports_sleep_ms(100);
                            }
                        } else if (handshake_result == -0x7700) {
                            // MBEDTLS_ERR_SSL_WANT_READ - normal, continue
                            ports_sleep_ms(10);
                        } else {
                            // Other errors - log and continue with small delay
                            LOGD("DTLS handshake error -0x%x (attempt %d/30)", static_cast<unsigned int>(-handshake_result), dtls_handshake_delay_counter_);
                            ports_sleep_ms(20);
                        }
                    } else {
                        LOGI("DTLS handshake attempts exceeded, checking if DTLS completed anyway");
                        // Sometimes DTLS completes but handshake returns error
                        // Check if SRTP sessions were created (indicating successful completion)
                        if (dtls_srtp_.get_state() == rtc::DtlsSrtpState::CONNECTED) {
                            LOGI("DTLS state shows connected, proceeding to COMPLETED");
    #if CONFIG_ENABLE_DATACHANNEL
                            if (config_.datachannel != DataChannelType::NONE && !sctp_) {
                                LOGI("SCTP create socket");
                                sctp_ = std::make_unique<rtc::SctpAssociation>();
                                sctp_->create_association(&dtls_srtp_);
                            }
    #endif
                            state_changed(PeerConnectionState::COMPLETED);
                        } else {
                            // DTLS handshake failed completely
                            LOGE("DTLS handshake failed after %d attempts, moving to FAILED state", dtls_handshake_delay_counter_);
                            state_changed(PeerConnectionState::FAILED);
                            // Reset counter for potential reconnection
                            dtls_handshake_delay_counter_ = 0;
                        }
                    }
                } else {
                    // DTLS already connected, move to COMPLETED state
                    LOGI("DTLS already connected, transitioning to COMPLETED");
                    
    #if CONFIG_ENABLE_DATACHANNEL
                    if (config_.datachannel != DataChannelType::NONE && !sctp_) {
                        LOGI("SCTP create socket");
                        sctp_ = std::make_unique<rtc::SctpAssociation>();
                        sctp_->create_association(&dtls_srtp_);
                    }
    #endif
                    state_changed(PeerConnectionState::COMPLETED);
                }
                break;
            }
                
            case PeerConnectionState::COMPLETED: {
                if (agent_.get_binding_request_time() > time_of_last_activity_) {
                    time_of_last_activity_ = agent_.get_binding_request_time();
                }

                // Initialize keepalive timer on first entry to COMPLETED state
                if (next_keepalive_time_ == 0) {
                    next_keepalive_time_ = current_time + 5000; // First keepalive in 5 seconds
                }
                
                // Check if it's time to send keepalive
                if (current_time >= next_keepalive_time_) {
                    agent_.connectivity_check();
                    
                    // Schedule next keepalive in 5 seconds regardless
                    next_keepalive_time_ = current_time + 5000;
                }
                
                if ((agent_ret_ = agent_.recv(recv_buf, sizeof(recv_buf))) > 0) {
                    LOGD("[%u]agent_recv %d", current_time, agent_ret_);
                    // schedule next keepalive in 5 seconds
                    next_keepalive_time_ = current_time + 5000;
                    time_of_last_activity_ = current_time ;
                    
                    if (rtc::RtcpProcessor::probe(recv_buf, agent_ret_)) {
                        LOGD("[%u]Got RTCP packet", current_time);
                        dtls_srtp_.decrypt_rtcp_packet(recv_buf, &agent_ret_);
                        incoming_rtcp(recv_buf, agent_ret_);
                        
                    } else if (rtc::DtlsSrtpSession::probe(recv_buf)) {
                        // Reuse recv_buf for DTLS decrypted data
                        int ret = dtls_srtp_.read(recv_buf, sizeof(recv_buf));
                        LOGD("[%u]Got DTLS data %d", current_time, ret);
                    
    #if CONFIG_ENABLE_DATACHANNEL
                        if (ret > 0 && sctp_) {
                            sctp_->incoming_data(reinterpret_cast<char*>(recv_buf), ret);
                        }
    #endif
                    } else if (rtc::RtpProcessor::validate_packet(recv_buf, agent_ret_)) {
                        LOGD("[%u]Got RTP packet, size: %d", current_time, agent_ret_);
                        
                        LOGD("[%u]Decrypting RTP packet", current_time);
                        dtls_srtp_.decrypt_rtp_packet(recv_buf, &agent_ret_);
                        LOGD("[%u]RTP packet decrypted, new size: %d", current_time, agent_ret_);
                        
                        ssrc = rtc::RtpProcessor::get_ssrc(recv_buf);
                        LOGD("Received RTP packet with SSRC: %u, remote_assrc: %u, remote_vssrc: %u", 
                            ssrc, remote_assrc_, remote_vssrc_);
                        if (ssrc == remote_assrc_ && artp_decoder_) {
                            LOGD("[%u]Decoding audio RTP packet", current_time);
                            artp_decoder_->decode(recv_buf, agent_ret_);
                        } else if (ssrc == remote_vssrc_ && vrtp_decoder_) {
                            LOGD("[%u]Decoding video RTP packet", current_time);
                            vrtp_decoder_->decode(recv_buf, agent_ret_);
                        } else {
                            LOGD("[%u]RTP packet SSRC mismatch - dropping packet", current_time);
                        }
                        
                    } else {
                        // Analyze unknown data
                        LOGD("[%u]Unknown data - size: %d, first bytes: %02X %02X",
                            current_time,
                            agent_ret_, recv_buf[0], recv_buf[1]);
                    }
                } else {
                    // 缓冲区中没有数据，等待下一次循环
                    retryTries = 0;
                }

                if ((CONFIG_KEEPALIVE_TIMEOUT > 0) && (current_time > time_of_last_activity_)) {
                    if ((current_time - time_of_last_activity_) > CONFIG_KEEPALIVE_TIMEOUT) {
                        LOGI("[%lu]keepalive timeout, last activity: %lu, diff: %lu", 
                                (unsigned long)current_time, (unsigned long)time_of_last_activity_, (unsigned long)(current_time - time_of_last_activity_));
                        state_changed(PeerConnectionState::CLOSED);
                    }
                }
            
                break;
            }
                
            case PeerConnectionState::FAILED:
            case PeerConnectionState::DISCONNECTED:
            case PeerConnectionState::CLOSED:
            default:
                retryTries = 0;
                break;
        }
    }
    
    return 0;
}

#if CONFIG_ENABLE_DATACHANNEL
int PeerConnection::create_datachannel(DecpChannelType channel_type, uint16_t priority,
                                      uint32_t reliability_parameter, const std::string& label,
                                      const std::string& protocol) {
    return create_datachannel_with_sid(channel_type, priority, reliability_parameter, 
                                      label, protocol, 0);
}

int PeerConnection::create_datachannel_with_sid(DecpChannelType channel_type, uint16_t priority,
                                               uint32_t reliability_parameter, 
                                               const std::string& label, const std::string& protocol, 
                                               uint16_t sid) {
    if (!sctp_ || !sctp_->is_connected()) {
        LOGE("sctp not connected");
        return -1;
    }
    
    int msg_size = 12 + label.length() + protocol.length();
    uint16_t priority_big_endian = htons(priority);
    uint32_t reliability_big_endian = ntohl(reliability_parameter);
    uint16_t label_length = htons(label.length());
    uint16_t protocol_length = htons(protocol.length());
    
    std::vector<char> msg(msg_size);
    char* msg_ptr = msg.data();
    
    msg_ptr[0] = static_cast<char>(rtc::DecpMsgType::DATA_CHANNEL_OPEN);
    msg_ptr[1] = static_cast<char>(channel_type);
    memcpy(msg_ptr + 2, &priority_big_endian, sizeof(uint16_t));
    memcpy(msg_ptr + 4, &reliability_big_endian, sizeof(uint32_t));
    memcpy(msg_ptr + 8, &label_length, sizeof(uint16_t));
    memcpy(msg_ptr + 10, &protocol_length, sizeof(uint16_t));
    memcpy(msg_ptr + 12, label.c_str(), label.length());
    memcpy(msg_ptr + 12 + label.length(), protocol.c_str(), protocol.length());
    
    return sctp_->outgoing_data(msg_ptr, msg_size, rtc::SctpDataPpid::CONTROL, sid);
}

int PeerConnection::datachannel_send(const std::string& message) {
    return datachannel_send_with_sid(message.c_str(), message.length(), 0);
}

int PeerConnection::datachannel_send(const void* data, size_t len) {
    return datachannel_send_with_sid(data, len, 0);
}

int PeerConnection::datachannel_send_with_sid(const void* data, size_t len, uint16_t sid) {
    if (!sctp_ || !sctp_->is_connected()) {
        LOGE("sctp not connected");
        return -1;
    }
    
    rtc::SctpDataPpid ppid = (config_.datachannel == DataChannelType::STRING) ? 
                             rtc::SctpDataPpid::STRING : rtc::SctpDataPpid::BINARY;
    
    return sctp_->outgoing_data(static_cast<const char*>(data), len, ppid, sid);
}

int PeerConnection::lookup_sid(const std::string& label, uint16_t& sid) const {
    if (!sctp_) {
        return -1;  // SCTP not initialized
    }
    return sctp_->lookup_sid(label, sid);
}

std::string PeerConnection::lookup_sid_label(uint16_t sid) const {
    if (!sctp_) {
        return "";  // SCTP not initialized
    }
    return sctp_->lookup_sid_label(sid);
}

bool PeerConnection::is_sctp_connected() const {
    return sctp_ && sctp_->is_connected();
}

void PeerConnection::on_datachannel(std::function<void(const char* msg, size_t len, uint16_t sid)> on_message,
                                   std::function<void()> on_open,
                                   std::function<void()> on_close) {
    on_datachannel_message_ = on_message;
    on_datachannel_open_ = on_open;
    on_datachannel_close_ = on_close;
    
    if (sctp_) {
        sctp_->set_on_open([this]() {
            if (on_datachannel_open_) {
                on_datachannel_open_();
            }
        });
        
        sctp_->set_on_close([this]() {
            if (on_datachannel_close_) {
                on_datachannel_close_();
            }
        });
        
        sctp_->set_on_message([this](const char* msg, size_t len, uint16_t sid) {
            if (on_datachannel_message_) {
                on_datachannel_message_(msg, len, sid);
            }
        });
    }
}
#endif

int PeerConnection::send_audio(const uint8_t* buf, size_t len) {
    if (state_ != PeerConnectionState::COMPLETED || !artp_encoder_) {
        printf("DEBUG: send_audio failed: state=%d, encoder=%p\n", static_cast<int>(state_), artp_encoder_.get());
        return -1;
    }
    int ret = artp_encoder_->encode(buf, len);
    return ret;
}

int PeerConnection::send_video(const uint8_t* buf, size_t len) {
    if (state_ != PeerConnectionState::COMPLETED || !vrtp_encoder_) {
        return -1;
    }
    return vrtp_encoder_->encode(buf, len);
}

void PeerConnection::set_remote_description(const std::string& sdp, SdpType type) {
    const char* sdp_cstr = sdp.c_str();
    char* start = const_cast<char*>(sdp_cstr);
    char* line = nullptr;
    char buf[256];
    uint32_t* ssrc = nullptr;
    rtc::DtlsSrtpRole role = rtc::DtlsSrtpRole::SERVER;
    bool is_update = false;
    
    while ((line = strstr(start, "\r\n"))) {
        strncpy(buf, start, line - start);
        buf[line - start] = '\0';
        
        if (strstr(buf, "a=setup:passive")) {
            role = rtc::DtlsSrtpRole::CLIENT;
        }
        
        if (strstr(buf, "a=fingerprint")) {
            dtls_srtp_.set_remote_fingerprint(std::string(buf + 22));
        }
        
        if (strstr(buf, "a=ice-ufrag") &&
            !agent_.get_remote_ufrag().empty() &&
            (strncmp(buf + strlen("a=ice-ufrag:"), agent_.get_remote_ufrag().c_str(), 
                    agent_.get_remote_ufrag().length()) == 0)) {
            is_update = true;
        }
        
        if (strstr(buf, "m=video")) {
            ssrc = &remote_vssrc_;
        } else if (strstr(buf, "m=audio")) {
            ssrc = &remote_assrc_;
        }
        
        if (strstr(buf, "a=ssrc:") && ssrc) {
            char* val_start = strstr(buf, "a=ssrc:");
            *ssrc = strtoul(val_start + 7, nullptr, 10);
            LOGD("Parsed SSRC: %u from line: %s", *ssrc, buf);
            if (ssrc == &remote_assrc_) {
                LOGD("Set remote audio SSRC: %u", *ssrc);
            } else if (ssrc == &remote_vssrc_) {
                LOGD("Set remote video SSRC: %u", *ssrc);
            }
        }
        
        start = line + 2;
    }
    
    if (is_update) {
        return;
    }
    
    // Update DTLS role based on remote SDP (careful reinit needed)
    LOGI("Remote SDP setup indicates we should be DTLS role: %s", (role == rtc::DtlsSrtpRole::CLIENT) ? "CLIENT" : "SERVER");
    
    // Only reinitialize if the role is different and we haven't started handshake yet
    LOGI("Current DTLS role: %s, state: %d, required role: %s", 
         (dtls_srtp_.get_role() == rtc::DtlsSrtpRole::CLIENT) ? "CLIENT" : "SERVER",
         static_cast<int>(dtls_srtp_.get_state()),
         (role == rtc::DtlsSrtpRole::CLIENT) ? "CLIENT" : "SERVER");
         
    if (dtls_srtp_.get_role() != role && dtls_srtp_.get_state() == rtc::DtlsSrtpState::INIT) {
        LOGI("Reinitializing DTLS with correct role");
        dtls_srtp_.deinit();
        dtls_srtp_.init(role, this);
    }
    
    // Set UDP callbacks for DTLS transport
    dtls_srtp_.set_udp_callbacks(
        [this](const uint8_t* buf, size_t len) -> int {
            int ret = agent_.send(buf, static_cast<int>(len));
            if (ret < 0) {
                LOGD("DTLS UDP send failed: %d", ret);
            }
            return ret;
        },
        [this](uint8_t* buf, size_t len) -> int {
            int ret = agent_.recv(buf, static_cast<int>(len));
            if (ret < 0) {
                // Don't log timeout as error - it's normal in non-blocking mode
                if (ret != 0) {  // 0 is timeout, negative is actual error
                    LOGD("DTLS UDP recv: %d", ret);
                }
            }
            return ret;
        });
    
    agent_.set_remote_description(const_cast<char*>(sdp_cstr));
    if (type == SdpType::ANSWER) {
        agent_.update_candidate_pairs();
        state_changed(PeerConnectionState::CHECKING);
    }
}

std::string PeerConnection::create_sdp(SdpType sdp_type) {
    rtc::DtlsSrtpRole role = rtc::DtlsSrtpRole::SERVER;
    
#if CONFIG_ENABLE_DATACHANNEL
    // SCTP connection state is managed internally by SctpAssociation
#endif
    
    switch (sdp_type) {
        case SdpType::OFFER:
            role = rtc::DtlsSrtpRole::SERVER;
            agent_.clear_candidates();
            agent_.set_mode(rtc::AgentMode::CONTROLLING);
            break;
        case SdpType::ANSWER:
            role = rtc::DtlsSrtpRole::CLIENT;
            agent_.set_mode(rtc::AgentMode::CONTROLLED);
            break;
    }
    
    // Initialize DTLS for local SDP generation (role will be corrected later)
    dtls_srtp_.init(role, this);
    
    // Set UDP callbacks for DTLS transport
    dtls_srtp_.set_udp_callbacks(
        [this](const uint8_t* buf, size_t len) -> int {
            int ret = agent_.send(buf, static_cast<int>(len));
            if (ret < 0) {
                LOGD("DTLS UDP send failed: %d", ret);
            }
            return ret;
        },
        [this](uint8_t* buf, size_t len) -> int {
            int ret = agent_.recv(buf, static_cast<int>(len));
            if (ret < 0) {
                // Don't log timeout as error - it's normal in non-blocking mode
                if (ret != 0) {  // 0 is timeout, negative is actual error
                    LOGD("DTLS UDP recv: %d", ret);
                }
            }
            return ret;
        });
    
    rtc::SdpBuilder sdp_builder;
    
    sdp_builder.create(config_.video_codec != MediaCodec::NONE,
                      config_.audio_codec != MediaCodec::NONE,
                      config_.datachannel != DataChannelType::NONE);
    
    agent_.create_ice_credential();
    sdp_builder.append("a=ice-ufrag:%s", agent_.get_local_ufrag().c_str());
    sdp_builder.append("a=ice-pwd:%s", agent_.get_local_upwd().c_str());
    sdp_builder.append("a=fingerprint:sha-256 %s", dtls_srtp_.get_local_fingerprint().c_str());
    
    const char* setup_value = (role == rtc::DtlsSrtpRole::SERVER) ? 
                              "a=setup:passive" : "a=setup:active";
    sdp_builder.append("%s", setup_value);
    
    if (config_.video_codec == MediaCodec::H264 && vrtp_encoder_) {
        sdp_builder.append_h264(vrtp_encoder_->get_ssrc());
    }
    
    switch (config_.audio_codec) {
        case MediaCodec::PCMA:
            if (artp_encoder_) {
                sdp_builder.append_pcma(artp_encoder_->get_ssrc());
            }
            break;
        case MediaCodec::PCMU:
            if (artp_encoder_) {
                sdp_builder.append_pcmu(artp_encoder_->get_ssrc());
            }
            break;
        case MediaCodec::OPUS:
            if (artp_encoder_) {
                sdp_builder.append_opus(artp_encoder_->get_ssrc());
            }
            break;
        default:
            break;
    }
    
#if CONFIG_ENABLE_DATACHANNEL
    if (config_.datachannel != DataChannelType::NONE) {
        sdp_builder.append_datachannel();
    }
#endif
    
    local_description_created_ = true;
    
    agent_.gather_candidate("", "", "");  // host address
    for (const auto& ice_server : config_.ice_servers) {
        if (!ice_server.urls.empty()) {
            LOGI("ice server: %s", ice_server.urls.c_str());
            agent_.gather_candidate(ice_server.urls, 
                                 ice_server.username.empty() ? "" : ice_server.username,
                                 ice_server.credential.empty() ? "" : ice_server.credential);
        }
    }
    
    std::string local_desc;
    agent_.get_local_description(local_desc);
    sdp_builder.append("%s", local_desc.c_str());
    
    sdp_ = sdp_builder.get_sdp();
    
    if (on_ice_candidate_) {
        on_ice_candidate_(sdp_);
    }
    
    return sdp_;
}

std::string PeerConnection::create_offer() {
    return create_sdp(SdpType::OFFER);
}

std::string PeerConnection::create_answer() {
    std::string sdp = create_sdp(SdpType::ANSWER);
    agent_.update_candidate_pairs();
    state_changed(PeerConnectionState::CHECKING);
    return sdp;
}

int PeerConnection::add_ice_candidate(const std::string& ice_candidate) {
    LOGD("Add candidate: %s", ice_candidate.c_str());
    return agent_.add_ice_candidate(ice_candidate);
}

void PeerConnection::on_ice_candidate(std::function<void(const std::string& sdp)> callback) {
    on_ice_candidate_ = callback;
}

void PeerConnection::on_ice_connection_state_change(std::function<void(PeerConnectionState state)> callback) {
    on_ice_connection_state_change_ = callback;
}

void PeerConnection::on_receiver_packet_loss(std::function<void(float fraction_loss, uint32_t total_loss)> callback) {
    on_receiver_packet_loss_ = callback;
}

void PeerConnection::on_outgoing_rtp_packet(uint8_t* data, size_t size, void* user_data) {
    auto* pc = static_cast<PeerConnection*>(user_data);
    pc->dtls_srtp_.encrypt_rtp_packet(data, reinterpret_cast<int*>(&size));
    pc->agent_.send(data, size);
}


void PeerConnection::incoming_rtcp(uint8_t* buf, size_t len) {
    rtc::RtcpHeader* rtcp_header;
    size_t pos = 0;
    
    while (pos < len) {
        rtcp_header = reinterpret_cast<rtc::RtcpHeader*>(buf + pos);
        
        switch (rtcp_header->type) {
            case static_cast<uint8_t>(rtc::RtcpType::RR):
                LOGD("RTCP_RR");
                if (rtcp_header->rc > 0) {
                    // TODO: Handle receiver report
                }
                break;
            case static_cast<uint8_t>(rtc::RtcpType::PSFB): {
                int fmt = rtcp_header->rc;
                LOGD("RTCP_PSFB %d", fmt);
                // PLI and FIR
                if ((fmt == 1 || fmt == 4) && config_.on_request_keyframe) {
                    config_.on_request_keyframe();
                }
                break;
            }
            default:
                break;
        }
        
        pos += 4 * ntohs(rtcp_header->length) + 4;
    }
}

} // namespace rtc