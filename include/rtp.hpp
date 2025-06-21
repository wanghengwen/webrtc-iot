#ifndef RTP_HPP_
#define RTP_HPP_

#include <cstdint>
#include <vector>
#include <functional>
#include <memory>

#ifdef __BYTE_ORDER
#define __BIG_ENDIAN 4321
#define __LITTLE_ENDIAN 1234
#elif __APPLE__
#include <machine/endian.h>
#else
#include <endian.h>
#endif

#include "config.h"

// Forward declarations
struct PeerConnection;

namespace rtc {

enum class MediaCodec {
    NONE = 0,
    H264,
    OPUS,
    PCMU,
    PCMA,
    G722
};

enum class RtpPayloadType : uint8_t {
    PCMU = 0,
    PCMA = 8,
    G722 = 9,
    H264 = 96,
    OPUS = 111
};

enum class RtpSsrc : uint32_t {
    H264 = 1,
    PCMA = 4,
    PCMU = 5,
    OPUS = 6
};

#pragma pack(push, 1)
struct RtpHeader {
#if __BYTE_ORDER == __BIG_ENDIAN
    uint16_t version : 2;
    uint16_t padding : 1;
    uint16_t extension : 1;
    uint16_t csrccount : 4;
    uint16_t markerbit : 1;
    uint16_t type : 7;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t csrccount : 4;
    uint16_t extension : 1;
    uint16_t padding : 1;
    uint16_t version : 2;
    uint16_t type : 7;
    uint16_t markerbit : 1;
#endif
    uint16_t seq_number;
    uint32_t timestamp;
    uint32_t ssrc;
};

struct RtpPacket {
    RtpHeader header;
    uint8_t payload[CONFIG_MTU];
};
#pragma pack(pop)

using RtpOnPacketCallback = std::function<void(const uint8_t* packet, size_t bytes)>;

class RtpEncoder {
public:
    explicit RtpEncoder(MediaCodec codec = MediaCodec::NONE, RtpOnPacketCallback callback = nullptr);
    ~RtpEncoder() = default;
    
    // Copy and move operations
    RtpEncoder(const RtpEncoder&) = delete;
    RtpEncoder& operator=(const RtpEncoder&) = delete;
    RtpEncoder(RtpEncoder&&) = default;
    RtpEncoder& operator=(RtpEncoder&&) = default;
    
    int encode(const uint8_t* data, size_t size);
    void set_on_packet_callback(RtpOnPacketCallback callback) { on_packet_ = callback; }
    
    // Getters and setters
    uint16_t get_seq_number() const { return seq_number_; }
    uint32_t get_ssrc() const { return ssrc_; }
    uint32_t get_timestamp() const { return timestamp_; }
    MediaCodec get_codec() const { return codec_; }
    
    void set_ssrc(uint32_t ssrc) { ssrc_ = ssrc; }
    void set_timestamp_increment(uint32_t increment) { timestamp_increment_ = increment; }

private:
    MediaCodec codec_;
    RtpOnPacketCallback on_packet_;
    uint16_t seq_number_;
    uint32_t ssrc_;
    uint32_t timestamp_;
    uint32_t timestamp_increment_;
    std::vector<uint8_t> buffer_;
    
    int encode_h264_single(const uint8_t* data, size_t size);
    int encode_h264_fragmented(const uint8_t* data, size_t size);
    int encode_audio(const uint8_t* data, size_t size);
    
    void send_packet(const uint8_t* payload, size_t payload_size, bool marker = false);
};

class RtpDecoder {
public:
    explicit RtpDecoder(MediaCodec codec = MediaCodec::NONE, RtpOnPacketCallback callback = nullptr);
    ~RtpDecoder() = default;
    
    // Copy and move operations
    RtpDecoder(const RtpDecoder&) = delete;
    RtpDecoder& operator=(const RtpDecoder&) = delete;
    RtpDecoder(RtpDecoder&&) = default;
    RtpDecoder& operator=(RtpDecoder&&) = default;
    
    int decode(const uint8_t* data, size_t size);
    void set_on_packet_callback(RtpOnPacketCallback callback) { on_packet_ = callback; }
    
    MediaCodec get_codec() const { return codec_; }

private:
    MediaCodec codec_;
    RtpOnPacketCallback on_packet_;
    std::vector<uint8_t> reassembly_buffer_;
    uint16_t last_seq_;
    bool first_packet_;
    
    int decode_h264(const uint8_t* payload, size_t size, bool marker);
    int decode_audio(const uint8_t* payload, size_t size);
};

class RtpProcessor {
public:
    RtpProcessor() = default;
    ~RtpProcessor() = default;
    
    static bool validate_packet(const uint8_t* packet, size_t size);
    static uint32_t get_ssrc(const uint8_t* packet);
    static uint16_t get_sequence_number(const uint8_t* packet);
    static uint32_t get_timestamp(const uint8_t* packet);
    static RtpPayloadType get_payload_type(const uint8_t* packet);
    static bool get_marker_bit(const uint8_t* packet);
    
    static const uint8_t* get_payload(const uint8_t* packet, size_t& payload_size);
};

} // namespace rtc

#endif  // RTP_HPP_