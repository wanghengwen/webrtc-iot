#include "rtcp.hpp"
#include <cstring>
#include <arpa/inet.h>

extern "C" {
#include "address.h"
}

namespace rtc {

RtcpPli::RtcpPli(uint32_t ssrc) : ssrc_(ssrc) {
}

std::vector<uint8_t> RtcpPli::serialize() const {
    std::vector<uint8_t> packet(12);
    
    RtcpHeader* rtcp_header = reinterpret_cast<RtcpHeader*>(packet.data());
    rtcp_header->version = 2;
    rtcp_header->type = static_cast<uint8_t>(RtcpType::PSFB);
    rtcp_header->rc = 1;
    rtcp_header->length = htons((packet.size() / 4) - 1);
    
    uint32_t ssrc_be = htonl(ssrc_);
    memcpy(packet.data() + 8, &ssrc_be, 4);
    
    return packet;
}

bool RtcpPli::parse(const uint8_t* data, size_t size) {
    if (!data || size < 12) {
        return false;
    }
    
    const RtcpHeader* header = reinterpret_cast<const RtcpHeader*>(data);
    if (header->type != static_cast<uint8_t>(RtcpType::PSFB) || header->rc != 1) {
        return false;
    }
    
    memcpy(&ssrc_, data + 8, 4);
    ssrc_ = ntohl(ssrc_);
    return true;
}

RtcpFirPacket::RtcpFirPacket(int seq_nr) : seq_nr_(seq_nr) {
}

std::vector<uint8_t> RtcpFirPacket::serialize() const {
    std::vector<uint8_t> packet(20, 0);
    
    RtcpHeader* rtcp = reinterpret_cast<RtcpHeader*>(packet.data());
    rtcp->version = 2;
    rtcp->type = static_cast<uint8_t>(RtcpType::PSFB);
    rtcp->rc = 4;
    rtcp->length = htons((packet.size() / 4) - 1);
    
    RtcpFb* rtcp_fb = reinterpret_cast<RtcpFb*>(rtcp);
    RtcpFir* fir = reinterpret_cast<RtcpFir*>(rtcp_fb->fci);
    fir->seqnr = htonl(seq_nr_ << 24);
    
    return packet;
}

bool RtcpFirPacket::parse(const uint8_t* data, size_t size) {
    if (!data || size < 20) {
        return false;
    }
    
    const RtcpHeader* header = reinterpret_cast<const RtcpHeader*>(data);
    if (header->type != static_cast<uint8_t>(RtcpType::PSFB) || header->rc != 4) {
        return false;
    }
    
    const RtcpFb* rtcp_fb = reinterpret_cast<const RtcpFb*>(header);
    const RtcpFir* fir = reinterpret_cast<const RtcpFir*>(rtcp_fb->fci);
    seq_nr_ = (ntohl(fir->seqnr) >> 24) & 0xFF;
    
    return true;
}

RtcpReceiverReport::RtcpReceiverReport() {
    memset(&report_, 0, sizeof(report_));
}

std::vector<uint8_t> RtcpReceiverReport::serialize() const {
    std::vector<uint8_t> packet(sizeof(RtcpRr));
    memcpy(packet.data(), &report_, sizeof(RtcpRr));
    return packet;
}

bool RtcpReceiverReport::parse(const uint8_t* data, size_t size) {
    if (!data || size < sizeof(RtcpRr)) {
        return false;
    }
    
    memcpy(&report_, data, sizeof(RtcpRr));
    return true;
}

bool RtcpProcessor::probe(const uint8_t* packet, size_t size) {
    if (size < 8) {
        return false;
    }

    const RtcpHeader* header = reinterpret_cast<const RtcpHeader*>(packet);
    // RTCP packet types are in range 200-207 (SR, RR, SDES, BYE, APP, RTPFB, PSFB, XR)
    // Also check version = 2
    return (header->version == 2 && header->type >= 200 && header->type <= 207);
}

std::unique_ptr<RtcpPacket> RtcpProcessor::parse(const uint8_t* packet, size_t size) {
    if (!packet || size < 8) {
        return nullptr;
    }
    
    const RtcpHeader* header = reinterpret_cast<const RtcpHeader*>(packet);
    RtcpType type = static_cast<RtcpType>(header->type);
    
    switch (type) {
        case RtcpType::PSFB: {
            if (header->rc == 1 && size >= 12) {
                auto pli = std::make_unique<RtcpPli>();
                if (pli->parse(packet, size)) {
                    return std::move(pli);
                }
            } else if (header->rc == 4 && size >= 20) {
                auto fir = std::make_unique<RtcpFirPacket>();
                if (fir->parse(packet, size)) {
                    return std::move(fir);
                }
            }
            break;
        }
        case RtcpType::RR: {
            auto rr = std::make_unique<RtcpReceiverReport>();
            if (rr->parse(packet, size)) {
                return std::move(rr);
            }
            break;
        }
        default:
            break;
    }
    
    return nullptr;
}

std::vector<uint8_t> RtcpProcessor::create_pli(uint32_t ssrc) {
    RtcpPli pli(ssrc);
    return pli.serialize();
}

std::vector<uint8_t> RtcpProcessor::create_fir(int& seq_nr) {
    seq_nr = (seq_nr + 1) % 256;
    RtcpFirPacket fir(seq_nr);
    return fir.serialize();
}

rtc::RtcpRr RtcpProcessor::parse_receiver_report(const uint8_t* packet) {
    rtc::RtcpRr rtcp_rr;
    memcpy(&rtcp_rr.header, packet, sizeof(rtcp_rr.header));
    memcpy(&rtcp_rr.report_block[0], packet + 8, 6 * sizeof(uint32_t));
    return rtcp_rr;
}

} // namespace rtc