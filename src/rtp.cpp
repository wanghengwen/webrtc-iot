#include "rtp.hpp"
#include <cstring>
#include <arpa/inet.h>

#include "address.h"
#include "utils.h"

namespace rtc {

// H.264 specific constants
enum class RtpH264Type : uint8_t {
    NALU = 23,
    FU_A = 28
};

struct NaluHeader {
    uint8_t type : 5;
    uint8_t nri : 2;
    uint8_t f : 1;
};

struct FuHeader {
    uint8_t type : 5;
    uint8_t r : 1;
    uint8_t e : 1;
    uint8_t s : 1;
};

const size_t RTP_PAYLOAD_SIZE = CONFIG_MTU - sizeof(RtpHeader);
const size_t FU_PAYLOAD_SIZE = CONFIG_MTU - sizeof(RtpHeader) - sizeof(FuHeader) - sizeof(NaluHeader);

RtpEncoder::RtpEncoder(MediaCodec codec, RtpOnPacketCallback callback) 
    : codec_(codec)
    , on_packet_(callback)
    , seq_number_(0)
    , ssrc_(0)
    , timestamp_(0)
    , timestamp_increment_(90000 / 25) // Default for video 25fps
{
    buffer_.resize(CONFIG_MTU + 128);
    
    switch (codec_) {
        case MediaCodec::H264:
            ssrc_ = static_cast<uint32_t>(RtpSsrc::H264);
            timestamp_increment_ = 90000 / 25; // 25fps
            break;
        case MediaCodec::PCMA:
            ssrc_ = static_cast<uint32_t>(RtpSsrc::PCMA);
            timestamp_increment_ = 160; // 8kHz, 20ms
            break;
        case MediaCodec::PCMU:
            ssrc_ = static_cast<uint32_t>(RtpSsrc::PCMU);
            timestamp_increment_ = 160; // 8kHz, 20ms
            break;
        case MediaCodec::OPUS:
            ssrc_ = static_cast<uint32_t>(RtpSsrc::OPUS);
            timestamp_increment_ = 960; // 48kHz, 20ms
            break;
        default:
            break;
    }
}

void RtpEncoder::send_packet(const uint8_t* payload, size_t payload_size, bool marker) {
    RtpPacket* rtp_packet = reinterpret_cast<RtpPacket*>(buffer_.data());
    
    rtp_packet->header.version = 2;
    rtp_packet->header.padding = 0;
    rtp_packet->header.extension = 0;
    rtp_packet->header.csrccount = 0;
    rtp_packet->header.markerbit = marker ? 1 : 0;
    
    switch (codec_) {
        case MediaCodec::H264:
            rtp_packet->header.type = static_cast<uint8_t>(RtpPayloadType::H264);
            break;
        case MediaCodec::PCMA:
            rtp_packet->header.type = static_cast<uint8_t>(RtpPayloadType::PCMA);
            break;
        case MediaCodec::PCMU:
            rtp_packet->header.type = static_cast<uint8_t>(RtpPayloadType::PCMU);
            break;
        case MediaCodec::OPUS:
            rtp_packet->header.type = static_cast<uint8_t>(RtpPayloadType::OPUS);
            break;
        default:
            rtp_packet->header.type = 0;
            break;
    }
    
    rtp_packet->header.seq_number = htons(seq_number_++);
    rtp_packet->header.timestamp = htonl(timestamp_);
    rtp_packet->header.ssrc = htonl(ssrc_);
    
    memcpy(rtp_packet->payload, payload, payload_size);
    
    if (on_packet_) {
        on_packet_(buffer_.data(), sizeof(RtpHeader) + payload_size);
    }
}

int RtpEncoder::encode_h264_single(const uint8_t* data, size_t size) {
    if (size <= RTP_PAYLOAD_SIZE) {
        send_packet(data, size, true);
        return 0;
    }
    return encode_h264_fragmented(data, size);
}

int RtpEncoder::encode_h264_fragmented(const uint8_t* data, size_t size) {
    if (size <= 1) return -1;
    
    const NaluHeader* nalu_header = reinterpret_cast<const NaluHeader*>(data);
    size_t remaining = size - 1;
    const uint8_t* payload = data + 1;
    
    while (remaining > 0) {
        size_t chunk_size = std::min(remaining, FU_PAYLOAD_SIZE);
        bool is_first = (remaining == size - 1);
        bool is_last = (remaining == chunk_size);
        
        // Create FU-A header
        uint8_t fu_packet[CONFIG_MTU];
        NaluHeader* fu_indicator = reinterpret_cast<NaluHeader*>(fu_packet);
        fu_indicator->f = 0;
        fu_indicator->nri = nalu_header->nri;
        fu_indicator->type = static_cast<uint8_t>(RtpH264Type::FU_A);
        
        FuHeader* fu_header = reinterpret_cast<FuHeader*>(fu_packet + 1);
        fu_header->s = is_first ? 1 : 0;
        fu_header->e = is_last ? 1 : 0;
        fu_header->r = 0;
        fu_header->type = nalu_header->type;
        
        memcpy(fu_packet + 2, payload, chunk_size);
        
        send_packet(fu_packet, chunk_size + 2, is_last);
        
        payload += chunk_size;
        remaining -= chunk_size;
    }
    
    return 0;
}

int RtpEncoder::encode_audio(const uint8_t* data, size_t size) {
    if (size <= RTP_PAYLOAD_SIZE) {
        send_packet(data, size, true);
        return 0;
    }
    return -1; // Audio packets should not be fragmented
}

int RtpEncoder::encode(const uint8_t* data, size_t size) {
    if (!data || size == 0) return -1;
    
    int result = -1;
    
    switch (codec_) {
        case MediaCodec::H264:
            result = encode_h264_single(data, size);
            break;
        case MediaCodec::PCMA:
        case MediaCodec::PCMU:
        case MediaCodec::OPUS:
            result = encode_audio(data, size);
            break;
        default:
            break;
    }
    
    if (result == 0) {
        timestamp_ += timestamp_increment_;
    }
    
    return result;
}

RtpDecoder::RtpDecoder(MediaCodec codec, RtpOnPacketCallback callback) 
    : codec_(codec)
    , on_packet_(callback)
    , last_seq_(0)
    , first_packet_(true) {
    // Reduce buffer size for audio (1200 bytes), keep larger for video
    if (codec == MediaCodec::H264) {
        reassembly_buffer_.reserve(65536); // 64KB buffer for H264 reassembly
    } else {
        reassembly_buffer_.reserve(1200); // 1200 bytes for audio
    }
}

int RtpDecoder::decode_h264(const uint8_t* payload, size_t size, bool marker) {
    if (size < 1) return -1;
    
    const NaluHeader* nalu_header = reinterpret_cast<const NaluHeader*>(payload);
    
    if (nalu_header->type < 24) {
        // Single NAL unit packet
        reassembly_buffer_.clear();
        reassembly_buffer_.insert(reassembly_buffer_.end(), payload, payload + size);
        
        if (on_packet_) {
            on_packet_(reassembly_buffer_.data(), reassembly_buffer_.size());
        }
    } else if (nalu_header->type == static_cast<uint8_t>(RtpH264Type::FU_A)) {
        // Fragmented unit
        if (size < 2) return -1;
        
        const FuHeader* fu_header = reinterpret_cast<const FuHeader*>(payload + 1);
        
        if (fu_header->s) {
            // Start of fragmented packet
            reassembly_buffer_.clear();
            
            // Reconstruct NAL header
            NaluHeader reconstructed_header;
            reconstructed_header.f = nalu_header->f;
            reconstructed_header.nri = nalu_header->nri;
            reconstructed_header.type = fu_header->type;
            
            reassembly_buffer_.push_back(*reinterpret_cast<uint8_t*>(&reconstructed_header));
        }
        
        // Add payload (skip FU indicator and FU header)
        reassembly_buffer_.insert(reassembly_buffer_.end(), payload + 2, payload + size);
        
        if (fu_header->e && on_packet_) {
            // End of fragmented packet
            on_packet_(reassembly_buffer_.data(), reassembly_buffer_.size());
        }
    }
    
    return 0;
}

int RtpDecoder::decode_audio(const uint8_t* payload, size_t size) {
    if (on_packet_) {
        on_packet_(payload, size);
    }
    return 0;
}

int RtpDecoder::decode(const uint8_t* data, size_t size) {
    if (!data || size < sizeof(RtpHeader)) return -1;
    
    const RtpHeader* header = reinterpret_cast<const RtpHeader*>(data);
    const uint8_t* payload = data + sizeof(RtpHeader);
    size_t payload_size = size - sizeof(RtpHeader);
    
    // Check sequence number (simple loss detection)
    uint16_t seq = ntohs(header->seq_number);
    if (!first_packet_ && seq != (last_seq_ + 1) % 65536) {
        LOGW("RTP packet loss detected: expected %d, got %d", last_seq_ + 1, seq);
    }
    last_seq_ = seq;
    first_packet_ = false;
    
    bool marker = header->markerbit;
    
    switch (codec_) {
        case MediaCodec::H264:
            return decode_h264(payload, payload_size, marker);
        case MediaCodec::PCMA:
        case MediaCodec::PCMU:
        case MediaCodec::OPUS:
            return decode_audio(payload, payload_size);
        default:
            return -1;
    }
}

bool RtpProcessor::validate_packet(const uint8_t* packet, size_t size) {
    if (size < 12) return false;
    
    const RtpHeader* rtp_header = reinterpret_cast<const RtpHeader*>(packet);
    return ((rtp_header->type < 64) || (rtp_header->type >= 96));
}

uint32_t RtpProcessor::get_ssrc(const uint8_t* packet) {
    const RtpHeader* rtp_header = reinterpret_cast<const RtpHeader*>(packet);
    return ntohl(rtp_header->ssrc);
}

uint16_t RtpProcessor::get_sequence_number(const uint8_t* packet) {
    const RtpHeader* rtp_header = reinterpret_cast<const RtpHeader*>(packet);
    return ntohs(rtp_header->seq_number);
}

uint32_t RtpProcessor::get_timestamp(const uint8_t* packet) {
    const RtpHeader* rtp_header = reinterpret_cast<const RtpHeader*>(packet);
    return ntohl(rtp_header->timestamp);
}

RtpPayloadType RtpProcessor::get_payload_type(const uint8_t* packet) {
    const RtpHeader* rtp_header = reinterpret_cast<const RtpHeader*>(packet);
    return static_cast<RtpPayloadType>(rtp_header->type);
}

bool RtpProcessor::get_marker_bit(const uint8_t* packet) {
    const RtpHeader* rtp_header = reinterpret_cast<const RtpHeader*>(packet);
    return rtp_header->markerbit != 0;
}

const uint8_t* RtpProcessor::get_payload(const uint8_t* packet, size_t& payload_size) {
    const RtpHeader* rtp_header = reinterpret_cast<const RtpHeader*>(packet);
    payload_size = 0; // This would need actual packet size to compute
    return reinterpret_cast<const uint8_t*>(rtp_header + 1);
}

} // namespace rtc
