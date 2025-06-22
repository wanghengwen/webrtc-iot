#include "agent.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/select.h>
#include <unistd.h>
#include <algorithm>
#include <iostream>
#include <sstream>

extern "C" {
#include "config.h"
#include "base64.h"
#include "ports.h"
#include "socket.h"
#include "stun.h"
#include "utils.h"
}

namespace rtc {

IceAgent::IceAgent() 
    : b_host_addr_(false)
    , binding_request_time_(0)
    , state_(AgentState::GATHERING_ENDED)
    , mode_(AgentMode::CONTROLLED)
    , selected_pair_(nullptr)
    , nominated_pair_(nullptr)
    , use_candidate_(false) {
    
    // Initialize UDP sockets
    udp_sockets_[0].fd = -1;
    udp_sockets_[1].fd = -1;
    
    // Clear transaction ID
    transaction_id_.fill(0);
}

IceAgent::~IceAgent() {
    destroy();
}

void IceAgent::clear_candidates() {
    local_candidates_.clear();
    remote_candidates_.clear();
    candidate_pairs_.clear();
    selected_pair_ = nullptr;
    nominated_pair_ = nullptr;
}

int IceAgent::create() {
    int ret;
    
    // Create IPv4 UDP socket
    if ((ret = udp_socket_open(&udp_sockets_[0], AF_INET, 0)) < 0) {
        LOGE("Failed to create UDP socket.");
        return ret;
    }
    LOGI("create IPv4 UDP socket: %d", udp_sockets_[0].fd);

#if CONFIG_IPV6
    // Create IPv6 UDP socket
    if ((ret = udp_socket_open(&udp_sockets_[1], AF_INET6, 0)) < 0) {
        LOGE("Failed to create IPv6 UDP socket.");
        return ret;
    }
    LOGI("create IPv6 UDP socket: %d", udp_sockets_[1].fd);
#endif

    clear_candidates();
    remote_ufrag_.clear();
    remote_upwd_.clear();
    
    return 0;
}

void IceAgent::destroy() {
    if (udp_sockets_[0].fd > 0) {
        udp_socket_close(&udp_sockets_[0]);
        udp_sockets_[0].fd = -1;
    }

#if CONFIG_IPV6
    if (udp_sockets_[1].fd > 0) {
        udp_socket_close(&udp_sockets_[1]);
        udp_sockets_[1].fd = -1;
    }
#endif
}

int IceAgent::socket_recv(Address* addr, uint8_t* buf, int len) {
    int ret = -1;
    int maxfd = -1;
    fd_set rfds;
    struct timeval tv;
    int addr_type[] = { AF_INET,
#if CONFIG_IPV6
                        AF_INET6,
#endif
    };

    tv.tv_sec = 0;
    tv.tv_usec = POLL_TIMEOUT * 1000;
    FD_ZERO(&rfds);

    for (size_t i = 0; i < sizeof(addr_type) / sizeof(addr_type[0]); i++) {
        if (udp_sockets_[i].fd > maxfd) {
            maxfd = udp_sockets_[i].fd;
        }
        if (udp_sockets_[i].fd >= 0) {
            FD_SET(udp_sockets_[i].fd, &rfds);
        }
    }

    ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0) {
        LOGE("select error");
    } else if (ret == 0) {
        // timeout
    } else {
        for (int i = 0; i < 2; i++) {
            if (FD_ISSET(udp_sockets_[i].fd, &rfds)) {
                std::memset(buf, 0, len);
                ret = udp_socket_recvfrom(&udp_sockets_[i], addr, buf, len);
                break;
            }
        }
    }

    return ret;
}

int IceAgent::socket_send(const Address* addr, const uint8_t* buf, int len) {
    switch (addr->family) {
        case AF_INET6:
            return udp_socket_sendto(&udp_sockets_[1], const_cast<Address*>(addr), buf, len);
        case AF_INET:
        default:
            return udp_socket_sendto(&udp_sockets_[0], const_cast<Address*>(addr), buf, len);
    }
    return -1;
}

int IceAgent::socket_recv_attempts(Address* addr, uint8_t* buf, int len, int maxtimes) {
    int ret = -1;
    for (int i = 0; i < maxtimes; i++) {
        if ((ret = socket_recv(addr, buf, len)) != 0) {
            break;
        }
    }
    return ret;
}

int IceAgent::create_host_addr() {
    const char* iface_prefx[] = {CONFIG_IFACE_PREFIX};
    int addr_type[] = { AF_INET,
#if CONFIG_IPV6
                        AF_INET6,
#endif
    };

    for (size_t i = 0; i < sizeof(addr_type) / sizeof(addr_type[0]); i++) {
        for (size_t j = 0; j < sizeof(iface_prefx) / sizeof(iface_prefx[0]); j++) {
            IceCandidate ice_candidate;
            
            // Create candidate with socket bind address
            ice_candidate.create(local_candidates_.size(), IceCandidateType::HOST, udp_sockets_[i].bind_addr);
            
            // Try to resolve host address
            Address temp_addr = ice_candidate.get_addr();
            if (ports_get_host_addr(&temp_addr, iface_prefx[j])) {
                ice_candidate.set_addr(temp_addr);
                local_candidates_.push_back(ice_candidate);
            }
        }
    }

    return 0;
}

int IceAgent::create_stun_addr(const Address* serv_addr) {
    int ret = -1;
    Address bind_addr;
    StunMessage send_msg;
    StunMessage recv_msg;
    std::memset(&send_msg, 0, sizeof(send_msg));
    std::memset(&recv_msg, 0, sizeof(recv_msg));

    stun_msg_create(&send_msg, STUN_CLASS_REQUEST | STUN_METHOD_BINDING);

    ret = socket_send(serv_addr, send_msg.buf, send_msg.size);

    if (ret == -1) {
        LOGE("Failed to send STUN Binding Request.");
        return ret;
    }

    ret = socket_recv_attempts(nullptr, recv_msg.buf, sizeof(recv_msg.buf), STUN_RECV_MAXTIMES);
    if (ret <= 0) {
        LOGD("Failed to receive STUN Binding Response.");
        return ret;
    }

    stun_parse_msg_buf(&recv_msg);
    std::memcpy(&bind_addr, &recv_msg.mapped_addr, sizeof(Address));
    
    IceCandidate ice_candidate;
    ice_candidate.create(local_candidates_.size(), IceCandidateType::SRFLX, bind_addr);
    local_candidates_.push_back(ice_candidate);
    
    return ret;
}

int IceAgent::create_turn_addr(const Address* serv_addr, const std::string& username, const std::string& credential) {
    int ret = -1;
    uint32_t attr = ntohl(0x11000000);
    Address turn_addr;
    StunMessage send_msg;
    StunMessage recv_msg;
    
    std::memset(&recv_msg, 0, sizeof(recv_msg));
    std::memset(&send_msg, 0, sizeof(send_msg));
    
    stun_msg_create(&send_msg, STUN_METHOD_ALLOCATE);
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REQUESTED_TRANSPORT, sizeof(attr), (char*)&attr);  // UDP
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_USERNAME, username.length(), const_cast<char*>(username.c_str()));

    ret = socket_send(serv_addr, send_msg.buf, send_msg.size);
    if (ret == -1) {
        LOGE("Failed to send TURN Binding Request.");
        return -1;
    }

    ret = socket_recv_attempts(nullptr, recv_msg.buf, sizeof(recv_msg.buf), STUN_RECV_MAXTIMES);
    if (ret <= 0) {
        LOGD("Failed to receive TURN Binding Response.");
        return ret;
    }

    stun_parse_msg_buf(&recv_msg);

    if (recv_msg.stunclass == STUN_CLASS_ERROR && recv_msg.stunmethod == STUN_METHOD_ALLOCATE) {
        std::memset(&send_msg, 0, sizeof(send_msg));
        stun_msg_create(&send_msg, STUN_METHOD_ALLOCATE);
        stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REQUESTED_TRANSPORT, sizeof(attr), (char*)&attr);  // UDP
        stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_USERNAME, username.length(), const_cast<char*>(username.c_str()));
        stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_NONCE, strlen(recv_msg.nonce), recv_msg.nonce);
        stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REALM, strlen(recv_msg.realm), recv_msg.realm);
        stun_msg_finish(&send_msg, STUN_CREDENTIAL_LONG_TERM, const_cast<char*>(credential.c_str()), credential.length());
    } else {
        LOGE("Invalid TURN Binding Response.");
        return -1;
    }

    ret = socket_send(serv_addr, send_msg.buf, send_msg.size);
    if (ret < 0) {
        LOGE("Failed to send TURN Binding Request.");
        return -1;
    }

    ret = socket_recv_attempts(nullptr, recv_msg.buf, sizeof(recv_msg.buf), STUN_RECV_MAXTIMES);
    if (ret <= 0) {
        LOGD("Failed to receive TURN Binding Response.");
        return ret;
    }

    stun_parse_msg_buf(&recv_msg);
    std::memcpy(&turn_addr, &recv_msg.relayed_addr, sizeof(Address));
    
    IceCandidate ice_candidate;
    ice_candidate.create(local_candidates_.size(), IceCandidateType::RELAY, turn_addr);
    local_candidates_.push_back(ice_candidate);
    
    return ret;
}

void IceAgent::gather_candidate(const std::string& urls, const std::string& username, const std::string& credential) {
    char hostname[64];
    char addr_string[ADDRSTRLEN];
    int addr_type[1] = {AF_INET};  // ipv6 no need stun
    Address resolved_addr;
    std::memset(hostname, 0, sizeof(hostname));

    if (urls.empty()) {
        create_host_addr();
        return;
    }

    size_t colon_pos = urls.find(':', 5);
    if (colon_pos == std::string::npos) {
        LOGE("Invalid URL");
        return;
    }

    int port = std::atoi(urls.c_str() + colon_pos + 1);
    if (port <= 0) {
        LOGE("Cannot parse port");
        return;
    }

    std::string hostname_str = urls.substr(5, colon_pos - 5);
    std::strncpy(hostname, hostname_str.c_str(), sizeof(hostname) - 1);

    for (size_t i = 0; i < sizeof(addr_type) / sizeof(addr_type[0]); i++) {
        if (ports_resolve_addr(hostname, &resolved_addr) == 0) {
            addr_set_port(&resolved_addr, port);
            addr_to_string(&resolved_addr, addr_string, sizeof(addr_string));
            LOGI("Resolved stun/turn server %s:%d", addr_string, port);

            if (urls.substr(0, 5) == "stun:") {
                LOGD("Create stun addr");
                create_stun_addr(&resolved_addr);
            } else if (urls.substr(0, 5) == "turn:") {
                LOGD("Create turn addr");
                create_turn_addr(&resolved_addr, username, credential);
            }
        }
    }
}

void IceAgent::create_ice_credential() {
    char local_ufrag_buf[ICE_UFRAG_LENGTH + 1];
    char local_upwd_buf[ICE_UPWD_LENGTH + 1];
    
    std::memset(local_ufrag_buf, 0, sizeof(local_ufrag_buf));
    std::memset(local_upwd_buf, 0, sizeof(local_upwd_buf));

    utils_random_string(local_ufrag_buf, 4);
    utils_random_string(local_upwd_buf, 24);
    
    local_ufrag_ = std::string(local_ufrag_buf);
    local_upwd_ = std::string(local_upwd_buf);
}

void IceAgent::get_local_description(std::string& description) const {
    description.clear();
    
    for (const auto& candidate : local_candidates_) {
        description += candidate.to_description();
    }

    // Remove trailing \r\n if present
    if (description.size() >= 2 && description.substr(description.size() - 2) == "\r\n") {
        description.pop_back();
        description.pop_back();
    }
    
    LOGD("local description:\n%s", description.c_str());
}

int IceAgent::send(const uint8_t* buf, int len) {
    if (nominated_pair_ == nullptr) {
        LOGE("No nominated pair available for sending");
        return -1;
    }
    
    Address remote_addr = nominated_pair_->get_remote()->get_addr();
    return socket_send(&remote_addr, buf, len);
}

void IceAgent::create_binding_response(StunMessage* msg, const Address* addr) {
    int size = 0;
    char username[584];
    char mapped_address[32];
    uint8_t mask[16];
    StunHeader* header;
    
    stun_msg_create(msg, STUN_CLASS_RESPONSE | STUN_METHOD_BINDING);
    header = (StunHeader*)msg->buf;
    std::memcpy(header->transaction_id, transaction_id_.data(), sizeof(header->transaction_id));
    
    std::snprintf(username, sizeof(username), "%s:%s", local_ufrag_.c_str(), remote_ufrag_.c_str());
    *((uint32_t*)mask) = htonl(MAGIC_COOKIE);
    std::memcpy(mask + 4, transaction_id_.data(), sizeof(transaction_id_));
    
    size = stun_set_mapped_address(mapped_address, mask, const_cast<Address*>(addr));
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS, size, mapped_address);
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_USERNAME, strlen(username), username);
    stun_msg_finish(msg, STUN_CREDENTIAL_SHORT_TERM, const_cast<char*>(local_upwd_.c_str()), local_upwd_.length());
}

void IceAgent::create_binding_request(StunMessage* msg) {
    uint64_t tie_breaker = 0;  // always be controlled
    
    stun_msg_create(msg, STUN_CLASS_REQUEST | STUN_METHOD_BINDING);
    char username[584];
    std::memset(username, 0, sizeof(username));
    std::snprintf(username, sizeof(username), "%s:%s", remote_ufrag_.c_str(), local_ufrag_.c_str());
    
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_USERNAME, strlen(username), username);
    
    uint64_t priority = nominated_pair_->get_priority();
    stun_msg_write_attr(msg, STUN_ATTR_TYPE_PRIORITY, 4, (char*)&priority);
    
    if (mode_ == AgentMode::CONTROLLING) {
        stun_msg_write_attr(msg, STUN_ATTR_TYPE_USE_CANDIDATE, 0, nullptr);
        stun_msg_write_attr(msg, STUN_ATTR_TYPE_ICE_CONTROLLING, 8, (char*)&tie_breaker);
    } else {
        stun_msg_write_attr(msg, STUN_ATTR_TYPE_ICE_CONTROLLED, 8, (char*)&tie_breaker);
    }
    
    stun_msg_finish(msg, STUN_CREDENTIAL_SHORT_TERM, const_cast<char*>(remote_upwd_.c_str()), remote_upwd_.length());
}

void IceAgent::process_stun_request(StunMessage* stun_msg, const Address* addr) {
    StunMessage msg;
    StunHeader* header;
    
    switch (stun_msg->stunmethod) {
        case STUN_METHOD_BINDING:
            if (stun_msg_is_valid(stun_msg->buf, stun_msg->size, const_cast<char*>(local_upwd_.c_str())) == 0) {
                header = (StunHeader*)stun_msg->buf;
                std::memcpy(transaction_id_.data(), header->transaction_id, sizeof(header->transaction_id));
                create_binding_response(&msg, addr);
                socket_send(addr, msg.buf, msg.size);
                binding_request_time_ = ports_get_epoch_time();
            }
            break;
        default:
            break;
    }
}

void IceAgent::process_stun_response(StunMessage* stun_msg) {
    switch (stun_msg->stunmethod) {
        case STUN_METHOD_BINDING:
            if (stun_msg_is_valid(stun_msg->buf, stun_msg->size, const_cast<char*>(remote_upwd_.c_str())) == 0) {
                if (nominated_pair_) {
                    nominated_pair_->set_state(IceCandidateState::SUCCEEDED);
                }
            }
            break;
        default:
            break;
    }
}

int IceAgent::recv(uint8_t* buf, int len) {
    int ret = -1;
    StunMessage stun_msg;
    Address addr;
    
    if ((ret = socket_recv(&addr, buf, len)) > 0 && stun_probe(buf, len) == 0) {
        std::memcpy(stun_msg.buf, buf, ret);
        stun_msg.size = ret;
        stun_parse_msg_buf(&stun_msg);
        
        switch (stun_msg.stunclass) {
            case STUN_CLASS_REQUEST:
                process_stun_request(&stun_msg, &addr);
                break;
            case STUN_CLASS_RESPONSE:
                process_stun_response(&stun_msg);
                break;
            case STUN_CLASS_ERROR:
                break;
            default:
                break;
        }
        ret = 0;
    }
    return ret;
}

void IceAgent::set_remote_description(const std::string& description) {
    LOGD("Set remote description:\n%s", description.c_str());

    std::istringstream iss(description);
    std::string line;

    while (std::getline(iss, line)) {
        // Remove carriage return if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        if (line.substr(0, 12) == "a=ice-ufrag:") {
            remote_ufrag_ = line.substr(12);
        } else if (line.substr(0, 10) == "a=ice-pwd:") {
            remote_upwd_ = line.substr(10);
        } else if (line.substr(0, 12) == "a=candidate:") {
            IceCandidate candidate;
            if (candidate.from_description(line)) {
                // Check for duplicate foundations
                bool found = false;
                for (const auto& existing : remote_candidates_) {
                    if (existing.get_foundation() == candidate.get_foundation()) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    remote_candidates_.push_back(candidate);
                }
            }
        }
    }

    LOGD("remote ufrag: %s", remote_ufrag_.c_str());
    LOGD("remote upwd: %s", remote_upwd_.c_str());
}

void IceAgent::update_candidate_pairs() {
    candidate_pairs_.clear();
    
    // Create candidate pairs for matching address families
    for (size_t i = 0; i < local_candidates_.size(); i++) {
        for (size_t j = 0; j < remote_candidates_.size(); j++) {
            if (local_candidates_[i].get_addr().family == remote_candidates_[j].get_addr().family) {
                auto local_ptr = std::make_shared<IceCandidate>(local_candidates_[i]);
                auto remote_ptr = std::make_shared<IceCandidate>(remote_candidates_[j]);
                
                IceCandidatePair pair(local_ptr, remote_ptr);
                pair.set_state(IceCandidateState::FROZEN);
                candidate_pairs_.push_back(pair);
            }
        }
    }
    
    LOGD("candidate pairs num: %d", static_cast<int>(candidate_pairs_.size()));
}

int IceAgent::connectivity_check() {
    char addr_string[ADDRSTRLEN];
    uint8_t buf[1400];
    StunMessage msg;

    if (!nominated_pair_ || nominated_pair_->get_state() != IceCandidateState::INPROGRESS) {
        LOGI("nominated pair is not in progress");
        return -1;
    }

    std::memset(&msg, 0, sizeof(msg));

    if (nominated_pair_->get_conncheck() % CONNCHECK_PERIOD == 0) {
        Address remote_addr = nominated_pair_->get_remote()->get_addr();
        addr_to_string(&remote_addr, addr_string, sizeof(addr_string));
        LOGD("send binding request to remote ip: %s, port: %d", addr_string, remote_addr.port);
        create_binding_request(&msg);
        socket_send(&remote_addr, msg.buf, msg.size);
    }

    recv(buf, sizeof(buf));

    if (nominated_pair_->get_state() == IceCandidateState::SUCCEEDED) {
        selected_pair_ = nominated_pair_;
        return 0;
    }

    return -1;
}

int IceAgent::select_candidate_pair() {
    for (auto& pair : candidate_pairs_) {
        if (pair.get_state() == IceCandidateState::FROZEN) {
            // Nominate this pair
            nominated_pair_ = &pair;
            pair.set_conncheck(0);
            pair.set_state(IceCandidateState::INPROGRESS);
            return 0;
        } else if (pair.get_state() == IceCandidateState::INPROGRESS) {
            pair.set_conncheck(pair.get_conncheck() + 1);
            if (pair.get_conncheck() < CONNCHECK_MAX) {
                return 0;
            }
            pair.set_state(IceCandidateState::FAILED);
        } else if (pair.get_state() == IceCandidateState::FAILED) {
            // Continue to next pair
        } else if (pair.get_state() == IceCandidateState::SUCCEEDED) {
            selected_pair_ = &pair;
            return 0;
        }
    }
    
    // All candidate pairs are failed
    return -1;
}

int IceAgent::add_ice_candidate(const std::string& ice_candidate) {
    LOGD("Add ICE candidate: %s", ice_candidate.c_str());
    
    // Parse the ICE candidate string (based on original C implementation)
    std::string candidate_start = ice_candidate;
    
    // Remove "a=" prefix if present
    if (candidate_start.substr(0, 2) == "a=") {
        candidate_start = candidate_start.substr(2);
    }
    
    // Must start with "candidate:"
    if (candidate_start.substr(0, 10) != "candidate:") {
        LOGE("Invalid ICE candidate format: missing 'candidate:' prefix");
        return -1;
    }
    
    candidate_start = candidate_start.substr(10); // Remove "candidate:"
    
    // Parse: foundation component transport priority address port typ type
    // Example: "448736988 1 udp 2122260223 172.17.0.1 49250 typ host"
    std::istringstream iss(candidate_start);
    std::string foundation, component_str, transport, priority_str, address_str, port_str, typ_str, type_str;
    
    if (!(iss >> foundation >> component_str >> transport >> priority_str >> 
          address_str >> port_str >> typ_str >> type_str)) {
        LOGE("Failed to parse ICE candidate description");
        return -1;
    }
    
    // Validate transport
    if (transport != "UDP" && transport != "udp") {
        LOGE("Only UDP transport is supported, got: %s", transport.c_str());
        return -1;
    }
    
    // Parse candidate type
    IceCandidateType cand_type;
    if (type_str == "host") {
        cand_type = IceCandidateType::HOST;
    } else if (type_str == "srflx") {
        cand_type = IceCandidateType::SRFLX;
    } else if (type_str == "prflx") {
        cand_type = IceCandidateType::PRFLX;
    } else if (type_str == "relay") {
        cand_type = IceCandidateType::RELAY;
    } else {
        LOGE("Unknown candidate type: %s", type_str.c_str());
        return -1;
    }
    
    // Create new ice candidate
    IceCandidate candidate;
    candidate.set_foundation(foundation);
    candidate.set_component(std::stoi(component_str));
    candidate.set_transport(transport);
    candidate.set_type(cand_type);
    candidate.set_state(IceCandidateState::WAITING);
    
    // Parse address
    Address addr;
    if (address_str.find("local") != std::string::npos) {
        // mDNS address - would need mdns_resolve_addr equivalent
        LOGW("mDNS addresses not fully supported yet: %s", address_str.c_str());
        return -1;
    } else {
        if (addr_from_string(address_str.c_str(), &addr) == 0) {
            LOGE("Failed to parse address: %s", address_str.c_str());
            return -1;
        }
    }
    
    addr_set_port(&addr, static_cast<uint16_t>(std::stoul(port_str)));
    candidate.set_addr(addr);
    
    // Add to remote candidates
    remote_candidates_.push_back(candidate);
    
    LOGD("Successfully added remote ICE candidate: %s", foundation.c_str());
    return 0;
}

} // namespace rtc