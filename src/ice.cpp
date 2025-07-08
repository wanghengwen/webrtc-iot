#include "ice.hpp"
#include <cstdio>
#include <cstring>
#include <cinttypes>

#include "address.h"
#include "mdns.h"
#include "ports.h"
#include "socket.h"
#include "utils.h"

namespace rtc {

IceCandidate::IceCandidate() 
    : component_(1)
    , priority_(0)
    , transport_("UDP")
    , type_(IceCandidateType::HOST)
    , state_(IceCandidateState::FROZEN) {
    memset(&addr_, 0, sizeof(addr_));
    memset(&raddr_, 0, sizeof(raddr_));
}

IceCandidate::IceCandidate(int foundation, IceCandidateType type, const Address& addr) 
    : IceCandidate() {
    create(foundation, type, addr);
}

uint8_t IceCandidate::get_type_preference() const {
    switch (type_) {
        case IceCandidateType::HOST:
            return 126;
        case IceCandidateType::SRFLX:
            return 100;
        case IceCandidateType::RELAY:
            return 0;
        default:
            return 0;
    }
}

uint16_t IceCandidate::get_local_preference() const {
    return addr_.port;
}

void IceCandidate::calculate_priority() {
    // priority = (2^24)*(type preference) + (2^8)*(local preference) + (256 - component ID)
    priority_ = (1 << 24) * get_type_preference() + (1 << 8) * get_local_preference() + (256 - component_);
}

void IceCandidate::create(int foundation, IceCandidateType type, const Address& addr) {
    addr_ = addr;
    type_ = type;
    foundation_ = std::to_string(foundation);
    component_ = 1; // 1: RTP, 2: RTCP
    transport_ = "UDP";
    calculate_priority();
}

std::string IceCandidate::to_description() const {
    char addr_string[ADDRSTRLEN];
    std::string typ_raddr;

    addr_to_string(&raddr_, addr_string, sizeof(addr_string));

    switch (type_) {
        case IceCandidateType::HOST:
            typ_raddr = "host";
            break;
        case IceCandidateType::SRFLX:
            typ_raddr = "srflx raddr " + std::string(addr_string) + " rport " + std::to_string(raddr_.port);
            break;
        case IceCandidateType::RELAY:
            typ_raddr = "relay raddr " + std::string(addr_string) + " rport " + std::to_string(raddr_.port);
            break;
        default:
            break;
    }

    addr_to_string(&addr_, addr_string, sizeof(addr_string));
    
    char description[512];
    snprintf(description, sizeof(description), "a=candidate:%s %d %s %" PRIu32 " %s %d typ %s\r\n",
             foundation_.c_str(),
             component_,
             transport_.c_str(),
             priority_,
             addr_string,
             addr_.port,
             typ_raddr.c_str());
    
    return std::string(description);
}

bool IceCandidate::from_description(const std::string& description) {
    char* candidate_start = const_cast<char*>(description.c_str());
    uint32_t port;
    char type[16];
    char addrstring[ADDRSTRLEN];
    char foundation[33];
    char transport[33];

    if (strncmp("a=", candidate_start, strlen("a=")) == 0) {
        candidate_start += strlen("a=");
    }
    candidate_start += strlen("candidate:");

    // a=candidate:448736988 1 udp 2122260223 172.17.0.1 49250 typ host generation 0 network-id 1 network-cost 50
    // a=candidate:udpcandidate 1 udp 120 192.168.1.102 8000 typ host
    if (sscanf(candidate_start, "%32s %d %32s %" PRIu32 " %s %" PRIu32 " typ %15s",
               foundation,
               &component_,
               transport,
               &priority_,
               addrstring,
               &port,
               type) != 7) {
        LOGE("Failed to parse ICE candidate description");
        return false;
    }

    foundation_ = std::string(foundation);
    transport_ = std::string(transport);

    if (strncmp(transport_.c_str(), "UDP", 3) != 0 && strncmp(transport_.c_str(), "udp", 3) != 0) {
        LOGE("Only UDP transport is supported");
        return false;
    }

    if (strncmp(type, "host", 4) == 0) {
        type_ = IceCandidateType::HOST;
    } else if (strncmp(type, "srflx", 5) == 0) {
        type_ = IceCandidateType::SRFLX;
    } else if (strncmp(type, "relay", 5) == 0) {
        type_ = IceCandidateType::RELAY;
    } else {
        LOGE("Unknown candidate type: %s", type);
        return false;
    }

    addr_set_port(&addr_, port);

    if (strstr(addrstring, "local") != NULL) {
        if (mdns_resolve_addr(addrstring, &addr_) == 0) {
            LOGW("Failed to resolve mDNS address");
            return false;
        }
    } else if (addr_from_string(addrstring, &addr_) == 0) {
        return false;
    }

    return true;
}

Address IceCandidate::get_local_address() const {
    return addr_;
}

// C compatibility methods removed for simplicity

IceCandidatePair::IceCandidatePair() 
    : state_(IceCandidateState::FROZEN)
    , conncheck_(0)
    , priority_(0) {
}

IceCandidatePair::IceCandidatePair(std::shared_ptr<IceCandidate> local, std::shared_ptr<IceCandidate> remote)
    : state_(IceCandidateState::FROZEN)
    , local_(local)
    , remote_(remote)
    , conncheck_(0) {
    calculate_priority();
}

void IceCandidatePair::calculate_priority() {
    if (local_ && remote_) {
        uint64_t G = std::max(local_->get_priority(), remote_->get_priority());
        uint64_t D = std::min(local_->get_priority(), remote_->get_priority());
        priority_ = (1ULL << 32) * G + 2 * D + (G > D ? 1 : 0);
    }
}

} // namespace rtc
