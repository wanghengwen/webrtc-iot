#ifndef PEER_CONNECTION_HPP_
#define PEER_CONNECTION_HPP_

#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdlib>

#include "config.h"
#include "agent.hpp"
#include "dtls_srtp.hpp"
#include "rtp.hpp"
#include "rtcp.hpp"
#if CONFIG_ENABLE_DATACHANNEL
#include "sctp.hpp"
#endif

namespace rtc {

enum class SdpType {
    OFFER = 0,
    ANSWER
};

enum class PeerConnectionState {
    CLOSED = 0,
    NEW,
    CHECKING,
    CONNECTED,
    COMPLETED,
    FAILED,
    DISCONNECTED
};

enum class DataChannelType {
    NONE = 0,
    STRING,
    BINARY
};

enum class DecpChannelType {
    RELIABLE = 0x00,
    RELIABLE_UNORDERED = 0x80,
    PARTIAL_RELIABLE_REXMIT = 0x01,
    PARTIAL_RELIABLE_REXMIT_UNORDERED = 0x81,
    PARTIAL_RELIABLE_TIMED = 0x02,
    PARTIAL_RELIABLE_TIMED_UNORDERED = 0x82
};

// MediaCodec is defined in rtp.hpp

struct IceServer {
    std::string urls;
    std::string username;
    std::string credential;
};

struct PeerConfiguration {
    std::vector<IceServer> ice_servers;
    
    MediaCodec audio_codec = MediaCodec::NONE;
    MediaCodec video_codec = MediaCodec::NONE;
    DataChannelType datachannel = DataChannelType::NONE;
    
    std::function<void(const uint8_t* data, size_t size)> on_audio_track;
    std::function<void(const uint8_t* data, size_t size)> on_video_track;
    std::function<void()> on_request_keyframe;
};

class PeerConnection {
public:
    PeerConnection();
    explicit PeerConnection(const PeerConfiguration& config);
    ~PeerConnection();

    // Delete copy constructor and assignment operator
    PeerConnection(const PeerConnection&) = delete;
    PeerConnection& operator=(const PeerConnection&) = delete;

    // Move constructor and assignment operator
    PeerConnection(PeerConnection&& other) noexcept;
    PeerConnection& operator=(PeerConnection&& other) noexcept;

    void close();
    
    PeerConnectionState get_state() const;
    const std::string& state_to_string() const;
    
    // Main processing loop
    int Run();
    
#if CONFIG_ENABLE_DATACHANNEL
    int create_datachannel(DecpChannelType channel_type, uint16_t priority, 
                          uint32_t reliability_parameter, const std::string& label, 
                          const std::string& protocol);
    
    int create_datachannel_with_sid(DecpChannelType channel_type, uint16_t priority,
                                   uint32_t reliability_parameter, const std::string& label,
                                   const std::string& protocol, uint16_t sid);
    
    int datachannel_send(const std::string& message);
    int datachannel_send(const void* data, size_t len);
    int datachannel_send_with_sid(const void* data, size_t len, uint16_t sid);
    
    int lookup_sid(const std::string& label, uint16_t& sid) const;
    std::string lookup_sid_label(uint16_t sid) const;
    
    bool is_sctp_connected() const;
    
    void on_datachannel(std::function<void(const char* msg, size_t len, uint16_t sid)> on_message,
                       std::function<void()> on_open,
                       std::function<void()> on_close);
#endif

    int send_audio(const uint8_t* packet, size_t bytes);
    int send_video(const uint8_t* packet, size_t bytes);
    
    void set_remote_description(const std::string& sdp, SdpType sdp_type);
    void set_local_description(const std::string& sdp, SdpType sdp_type);
    
    std::string create_offer();
    std::string create_answer();
    
    int add_ice_candidate(const std::string& ice_candidate);
    
    // Callback setters
    void on_ice_candidate(std::function<void(const std::string& sdp)> callback);
    void on_ice_connection_state_change(std::function<void(PeerConnectionState state)> callback);
    void on_receiver_packet_loss(std::function<void(float fraction_loss, uint32_t total_loss)> callback);

private:
    void initialize_with_config(const PeerConfiguration& config);
    void cleanup();
    void state_changed(PeerConnectionState new_state);
    std::string create_sdp(SdpType sdp_type);
    
    // Internal callback wrappers for C functions
    static void on_outgoing_rtp_packet(uint8_t* data, size_t size, void* user_data);
    
    void incoming_rtcp(uint8_t* buf, size_t len);

private:
    PeerConfiguration config_;
    PeerConnectionState state_;
    rtc::IceAgent agent_;
    rtc::DtlsSrtpSession dtls_srtp_;
    
#if CONFIG_ENABLE_DATACHANNEL
    std::unique_ptr<rtc::SctpAssociation> sctp_;
#endif

    std::string sdp_;
    
    int agent_ret_;
    bool local_description_created_;
    int dtls_handshake_delay_counter_;
    
    std::unique_ptr<rtc::RtpEncoder> artp_encoder_;
    std::unique_ptr<rtc::RtpEncoder> vrtp_encoder_;
    std::unique_ptr<rtc::RtpDecoder> vrtp_decoder_;
    std::unique_ptr<rtc::RtpDecoder> artp_decoder_;
    
    uint32_t remote_assrc_;
    uint32_t remote_vssrc_;
    
    // Keepalive management
    uint32_t next_keepalive_time_;
    uint32_t time_of_last_activity_;
    
    // Callback functions
    std::function<void(const std::string& sdp)> on_ice_candidate_;
    std::function<void(PeerConnectionState state)> on_ice_connection_state_change_;
    std::function<void(float fraction_loss, uint32_t total_loss)> on_receiver_packet_loss_;
    
#if CONFIG_ENABLE_DATACHANNEL
    std::function<void(const char* msg, size_t len, uint16_t sid)> on_datachannel_message_;
    std::function<void()> on_datachannel_open_;
    std::function<void()> on_datachannel_close_;
#endif
};

} // namespace rtc

#endif // PEER_CONNECTION_HPP_