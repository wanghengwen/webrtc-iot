/* 
 * NAT Traversal Solution:
 * 
 * This implementation handles the case where the server is behind NAT (e.g., WSL with NAT mode).
 * When the server has internal IPs (172.x) in its SDP but actually communicates from a NAT IP
 * (e.g., 192.168.3.148), we create peer-reflexive candidates dynamically.
 * 
 * Key behaviors:
 * 1. When receiving BINDING request from unknown address -> create peer-reflexive candidate
 * 2. As CONTROLLED role -> immediately nominate peer-reflexive pairs for NAT scenarios  
 * 3. Prioritize SUCCEEDED pairs over INPROGRESS ones for nomination
 * 4. For NAT scenarios, the first successful connection path is used immediately
 * 
 * This ensures connectivity even when one peer is behind NAT without public IP.
 */

#include "agent.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/select.h>
#include <unistd.h>
#include <algorithm>
#include <iostream>
#include <sstream>

#include "config.h"
#include "base64.h"
#include "ports.h"
#include "socket.h"
#include "stun.h"
#include "utils.h"

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
    
    // 预先分配空间以避免后续添加时重新分配
    local_candidates_.reserve(10);
    remote_candidates_.reserve(20);  // 包括原始候选和 peer-reflexive
    candidate_pairs_.reserve(32);
    
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
    static uint32_t timeout_count = 0;
    static uint32_t select_error_count = 0;
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
        select_error_count++;
        LOGE("select error #%lu: %s", (unsigned long)select_error_count, strerror(errno));
    } else if (ret == 0) {
        // timeout - 这是正常的，不需要每次都记录
        timeout_count++;
        if (timeout_count % 1000 == 0) {
            LOGD("socket_recv timeout count: %lu", (unsigned long)timeout_count);
        }
    } else {
        // 有数据可读
        for (int i = 0; i < 2; i++) {
            if (udp_sockets_[i].fd >= 0 && FD_ISSET(udp_sockets_[i].fd, &rfds)) {
                std::memset(buf, 0, len);
                ret = udp_socket_recvfrom(&udp_sockets_[i], addr, buf, len);
                
                // 移除调试日志
                break;
            }
        }
    }

    return ret;
}

int IceAgent::socket_send(const Address* addr, const uint8_t* buf, int len) {
    int ret = -1;
    
    switch (addr->family) {
        case AF_INET6:
            ret = udp_socket_sendto(&udp_sockets_[1], const_cast<Address*>(addr), buf, len);
            break;
        case AF_INET:
        default:
            ret = udp_socket_sendto(&udp_sockets_[0], const_cast<Address*>(addr), buf, len);
            break;
    }
    
    return ret;
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
    Address recv_addr;  // 添加接收地址变量
    StunMessage send_msg;
    StunMessage recv_msg;
    std::memset(&send_msg, 0, sizeof(send_msg));
    std::memset(&recv_msg, 0, sizeof(recv_msg));
    std::memset(&recv_addr, 0, sizeof(recv_addr));  // 初始化接收地址

    stun_msg_create(&send_msg, static_cast<uint16_t>(static_cast<uint16_t>(STUN_CLASS_REQUEST) | static_cast<uint16_t>(STUN_METHOD_BINDING)));

    ret = socket_send(serv_addr, send_msg.buf, send_msg.size);

    if (ret == -1) {
        LOGE("Failed to send STUN Binding Request.");
        return ret;
    }

    // 传入有效的地址指针而不是 nullptr
    ret = socket_recv_attempts(&recv_addr, recv_msg.buf, sizeof(recv_msg.buf), STUN_RECV_MAXTIMES);
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
    Address recv_addr;  // 添加接收地址变量
    StunMessage send_msg;
    StunMessage recv_msg;
    
    std::memset(&recv_msg, 0, sizeof(recv_msg));
    std::memset(&send_msg, 0, sizeof(send_msg));
    std::memset(&recv_addr, 0, sizeof(recv_addr));  // 初始化接收地址
    
    stun_msg_create(&send_msg, STUN_METHOD_ALLOCATE);
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_REQUESTED_TRANSPORT, sizeof(attr), (char*)&attr);  // UDP
    stun_msg_write_attr(&send_msg, STUN_ATTR_TYPE_USERNAME, username.length(), const_cast<char*>(username.c_str()));

    ret = socket_send(serv_addr, send_msg.buf, send_msg.size);
    if (ret == -1) {
        LOGE("Failed to send TURN Binding Request.");
        return -1;
    }

    // 传入有效的地址指针而不是 nullptr
    ret = socket_recv_attempts(&recv_addr, recv_msg.buf, sizeof(recv_msg.buf), STUN_RECV_MAXTIMES);
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

    // 传入有效的地址指针而不是 nullptr
    ret = socket_recv_attempts(&recv_addr, recv_msg.buf, sizeof(recv_msg.buf), STUN_RECV_MAXTIMES);
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
    
}

int IceAgent::send(const uint8_t* buf, int len) {
    if (nominated_pair_ == nullptr) {
        LOGE("No nominated pair available for sending");
        return -1;
    }
    
    // 确保 nominated pair 是成功状态
    if (nominated_pair_->get_state() != IceCandidateState::SUCCEEDED) {
        LOGW("Nominated pair not in SUCCEEDED state (current: %d)",
             static_cast<int>(nominated_pair_->get_state()));
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
    
    stun_msg_create(msg, static_cast<uint16_t>(static_cast<uint16_t>(STUN_CLASS_RESPONSE) | static_cast<uint16_t>(STUN_METHOD_BINDING)));
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
    
    stun_msg_create(msg, static_cast<uint16_t>(static_cast<uint16_t>(STUN_CLASS_REQUEST) | static_cast<uint16_t>(STUN_METHOD_BINDING)));
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

// Helper function to check if USE_CANDIDATE attribute is present
static bool has_use_candidate_attr(uint8_t* buf, size_t len) {
    StunHeader* header = (StunHeader*)buf;
    size_t offset = sizeof(StunHeader);
    
    while (offset < len) {
        if (offset + sizeof(StunAttribute) > len) break;
        
        StunAttribute* attr = (StunAttribute*)(buf + offset);
        uint16_t type = ntohs(attr->type);
        uint16_t attr_len = ntohs(attr->length);
        
        if (type == STUN_ATTR_TYPE_USE_CANDIDATE) {
            return true;
        }
        
        // Move to next attribute (4-byte aligned)
        offset += sizeof(StunAttribute) + ((attr_len + 3) & ~3);
    }
    return false;
}

void IceAgent::process_stun_request(StunMessage* stun_msg, const Address* addr) {
    StunMessage msg;
    StunHeader* header;
    char addr_str[ADDRSTRLEN];
    
    addr_to_string(addr, addr_str, sizeof(addr_str));
    
    switch (stun_msg->stunmethod) {
        case STUN_METHOD_BINDING:
            
            if (stun_msg_is_valid(stun_msg->buf, stun_msg->size, const_cast<char*>(local_upwd_.c_str())) == 0) {
                header = (StunHeader*)stun_msg->buf;
                std::memcpy(transaction_id_.data(), header->transaction_id, sizeof(header->transaction_id));
                
                // 创建并发送响应
                create_binding_response(&msg, addr);
                int ret = socket_send(addr, msg.buf, msg.size);
                
                if (ret > 0) {
                    
                    // 对于NAT场景，立即发送一个 BINDING REQUEST 回去
                    // 这有助于保持NAT映射并验证双向连通性
                    static uint32_t nat_keepalive_counter = 0;
                    nat_keepalive_counter++;
                    
                    // 每5个响应发送一个请求（避免太频繁）
                    if (nat_keepalive_counter % 5 == 1) {
                        StunMessage keepalive_msg;
                        create_binding_request(&keepalive_msg);
                        socket_send(addr, keepalive_msg.buf, keepalive_msg.size);
                    }
                    
                    // 更新或创建候选对
                    bool pair_found = false;
                    
                    // 先检查远程候选列表，看是否已经有这个地址
                    bool remote_candidate_exists = false;
                    for (size_t idx = 0; idx < remote_candidates_.size(); idx++) {
                        Address remote_addr = remote_candidates_[idx].get_addr();
                        if (addr_equal(&remote_addr, const_cast<Address*>(addr))) {
                            remote_candidate_exists = true;
                            LOGD("Remote candidate already exists at index %zu for %s:%d", idx, addr_str, addr->port);
                            break;
                        }
                    }
                    
                    // 输出当前的提名状态以便调试
                    if (nominated_pair_) {
                        Address nom_addr = nominated_pair_->get_remote()->get_addr();
                        char nom_str[ADDRSTRLEN];
                        addr_to_string(&nom_addr, nom_str, sizeof(nom_str));
                        LOGD("Current nominated pair: remote=%s:%d, state=%d", 
                             nom_str, nom_addr.port, static_cast<int>(nominated_pair_->get_state()));
                    } else {
                        LOGD("No nominated pair currently set");
                    }
                    
                    // 检查候选对列表
                    for (size_t idx = 0; idx < candidate_pairs_.size(); idx++) {
                        Address remote_addr = candidate_pairs_[idx].get_remote()->get_addr();
                        
                        if (addr_equal(&remote_addr, const_cast<Address*>(addr))) {
                            // 找到匹配的候选对，更新状态
                            if (candidate_pairs_[idx].get_state() != IceCandidateState::SUCCEEDED) {
                                candidate_pairs_[idx].set_state(IceCandidateState::SUCCEEDED);
                                LOGI("Candidate pair[%zu] with %s:%d marked as SUCCEEDED", idx, addr_str, addr->port);
                            } else {
                                LOGD("Candidate pair[%zu] with %s:%d already in SUCCEEDED state", idx, addr_str, addr->port);
                            }
                            
                            // 更新远程候选的地址（可能端口已变化）
                            // 这对NAT场景很重要，因为端口可能会变化
                            candidate_pairs_[idx].get_remote()->set_addr(*addr);
                            LOGD("Updated pair[%zu] remote address to %s:%d (latest received from)", 
                                 idx, addr_str, addr->port);
                            
                            // 检查是否需要提名该候选对
                            bool should_update_nomination = false;
                            
                            if (mode_ == AgentMode::CONTROLLED) {
                                // CONTROLLED 角色: 优先检查 USE-CANDIDATE
                                bool has_use_candidate = has_use_candidate_attr(stun_msg->buf, stun_msg->size);
                                
                                if (has_use_candidate) {
                                    // USE-CANDIDATE 表示 CONTROLLING 方要求使用这个候选对
                                    should_update_nomination = true;
                                    LOGI("[ICE-CONTROLLED] USE-CANDIDATE received for pair[%zu], must nominate", idx);
                                } else if (!nominated_pair_) {
                                    // 没有提名的候选对，使用第一个成功的
                                    should_update_nomination = true;
                                    LOGI("[ICE-CONTROLLED] No nominated pair yet, using first successful pair[%zu]", idx);
                                } else if (nominated_pair_->get_state() != IceCandidateState::SUCCEEDED) {
                                    // 当前提名的候选对不是成功状态，切换到成功的
                                    should_update_nomination = true;
                                    LOGI("[ICE-CONTROLLED] Current nominated pair not succeeded, switching to pair[%zu]", idx);
                                }
                            } else {
                                // CONTROLLING 角色: 主动提名
                                if (!nominated_pair_ || nominated_pair_->get_state() != IceCandidateState::SUCCEEDED) {
                                    should_update_nomination = true;
                                    LOGI("[ICE-CONTROLLING] Nominating successful pair[%zu]", idx);
                                }
                            }
                            
                            if (should_update_nomination) {
                                nominated_pair_ = &candidate_pairs_[idx];
                                LOGI("*** NOMINATED pair[%zu] for %s:%d (mode=%s) ***", 
                                     idx, addr_str, addr->port, 
                                     mode_ == AgentMode::CONTROLLED ? "CONTROLLED" : "CONTROLLING");
                            }
                            pair_found = true;
                            break;
                        }
                    }
                    
                    if (!pair_found && !remote_candidate_exists) {
                        // 来自未知地址的请求 - 根据 ICE 规范，这是 peer-reflexive candidate
                        // 当我们是 Controlled 角色时，收到 Controlling 方的 Binding Request 表示对方选择了这条路径
                        LOGI("BINDING request from new address %s:%d, creating peer-reflexive candidate", 
                             addr_str, addr->port);
                        
                        // 创建 peer-reflexive candidate
                        IceCandidate peer_reflexive_candidate;
                        peer_reflexive_candidate.create(remote_candidates_.size(), IceCandidateType::PRFLX, *addr);
                        
                        // 添加到远程候选列表
                        remote_candidates_.push_back(peer_reflexive_candidate);
                        LOGI("Added peer-reflexive candidate: %s:%d", addr_str, addr->port);
                        
                        // 为新的候选创建候选对
                        for (size_t i = 0; i < local_candidates_.size(); i++) {
                            if (local_candidates_[i].get_addr().family == addr->family) {
                                auto local_ptr = std::make_shared<IceCandidate>(local_candidates_[i]);
                                auto remote_ptr = std::make_shared<IceCandidate>(peer_reflexive_candidate);
                                
                                IceCandidatePair new_pair(local_ptr, remote_ptr);
                                new_pair.set_state(IceCandidateState::SUCCEEDED);  // 已收到请求，连接验证成功
                                
                                // 保存当前nominated pair的索引（如果有）
                                int nominated_idx = -1;
                                if (nominated_pair_) {
                                    for (size_t j = 0; j < candidate_pairs_.size(); j++) {
                                        if (&candidate_pairs_[j] == nominated_pair_) {
                                            nominated_idx = j;
                                            break;
                                        }
                                    }
                                }
                                
                                // 添加新的候选对
                                candidate_pairs_.push_back(new_pair);
                                
                                // 重新设置指针（因为vector可能重新分配内存）
                                if (nominated_idx >= 0) {
                                    nominated_pair_ = &candidate_pairs_[nominated_idx];
                                }
                                
                                // 根据 ICE 规范：
                                // - 如果我们是 Controlled 角色，收到的 Binding Request 可能包含 USE-CANDIDATE
                                // - 或者即使没有 USE-CANDIDATE，第一个成功的连接也应该被使用
                                // - 在 Aggressive Nomination 模式下，第一个成功的连接就是 nominated
                                
                                bool should_nominate = false;
                                
                                // 根据 ICE 规范处理 peer-reflexive 候选的提名
                                
                                if (mode_ == AgentMode::CONTROLLED) {
                                    // CONTROLLED 角色：检查是否有 USE-CANDIDATE 属性
                                    bool has_use_candidate = has_use_candidate_attr(stun_msg->buf, stun_msg->size);
                                    
                                    if (has_use_candidate) {
                                        // 收到 USE-CANDIDATE，必须提名这个候选对
                                        should_nominate = true;
                                        LOGI("[ICE-CONTROLLED] Received USE-CANDIDATE, nominating peer-reflexive pair from %s:%d", 
                                             addr_str, addr->port);
                                    } else {
                                        // 没有 USE-CANDIDATE，标记为成功但不提名
                                        LOGI("[ICE-CONTROLLED] Peer-reflexive pair created for %s:%d (no USE-CANDIDATE, not nominated)",
                                             addr_str, addr->port);
                                    }
                                } else {
                                    // CONTROLLING 角色：不应该因为收到请求就提名
                                    // 应该通过连接检查主动选择并发送 USE-CANDIDATE
                                    LOGI("[ICE-CONTROLLING] Peer-reflexive pair created for %s:%d (will nominate via connectivity check)", 
                                         addr_str, addr->port);
                                    // 不立即提名，让连接检查过程决定
                                    should_nominate = false;
                                }
                                
                                if (should_nominate) {
                                    // 设置或更新 nominated pair
                                    if (nominated_pair_ && nominated_pair_->get_state() == IceCandidateState::SUCCEEDED) {
                                        // 已有成功的 nominated pair
                                        Address current_remote = nominated_pair_->get_remote()->get_addr();
                                        char current_addr_str[ADDRSTRLEN];
                                        addr_to_string(&current_remote, current_addr_str, sizeof(current_addr_str));
                                        
                                        // 如果是同一个IP但不同端口，更新到新端口（NAT端口可能变化）
                                        if (current_remote.family == addr->family && 
                                            memcmp(&current_remote.sin.sin_addr, &addr->sin.sin_addr, sizeof(struct in_addr)) == 0 &&
                                            current_remote.port != addr->port) {
                                            LOGI("NAT port changed from %s:%d to %s:%d, updating nominated pair",
                                                 current_addr_str, current_remote.port, addr_str, addr->port);
                                            nominated_pair_ = &candidate_pairs_.back();
                                        } else {
                                            LOGI("New successful pair for %s:%d, but keeping current nominated pair %s:%d",
                                                 addr_str, addr->port, current_addr_str, current_remote.port);
                                        }
                                    } else {
                                        // 设置新的 nominated pair
                                        nominated_pair_ = &candidate_pairs_.back();
                                        LOGI("NOMINATED peer-reflexive pair for %s:%d (index=%zu)", 
                                             addr_str, addr->port, candidate_pairs_.size() - 1);
                                    }
                                } else {
                                    LOGI("Created backup peer-reflexive pair for %s:%d", addr_str, addr->port);
                                }
                                
                                LOGI("Created candidate pair [local %s -> remote %s:%d]",
                                     local_candidates_[i].to_description().c_str(), addr_str, addr->port);
                                break;
                            }
                        }
                    }
                } else {
                    LOGE("Failed to send BINDING response to %s:%d", addr_str, addr->port);
                }
                
                binding_request_time_ = ports_get_epoch_time();
            } else {
                LOGW("Invalid BINDING request from %s:%d (auth failed)", addr_str, addr->port);
            }
            break;
        default:
            LOGW("Unknown STUN method %d from %s:%d", stun_msg->stunmethod, addr_str, addr->port);
            break;
    }
}

void IceAgent::process_stun_response(StunMessage* stun_msg) {
    switch (stun_msg->stunmethod) {
        case STUN_METHOD_BINDING:
            if (stun_msg_is_valid(stun_msg->buf, stun_msg->size, const_cast<char*>(remote_upwd_.c_str())) == 0) {
                LOGI("Received valid BINDING response");
                if (nominated_pair_) {
                    if (nominated_pair_->get_state() != IceCandidateState::SUCCEEDED) {
                        nominated_pair_->set_state(IceCandidateState::SUCCEEDED);
                        
                        Address remote_addr = nominated_pair_->get_remote()->get_addr();
                        char addr_str[ADDRSTRLEN];
                        addr_to_string(&remote_addr, addr_str, sizeof(addr_str));
                        LOGI("Nominated pair with %s:%d marked as SUCCEEDED (via response)", 
                             addr_str, remote_addr.port);
                    }
                } else {
                    LOGW("Received BINDING response but no nominated pair set");
                }
            } else {
                LOGW("Invalid BINDING response (auth failed)");
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
    char addr_str[ADDRSTRLEN];
    
    if ((ret = socket_recv(&addr, buf, len)) > 0) {
        addr_to_string(&addr, addr_str, sizeof(addr_str));
        
        if (stun_probe(buf, len) == 0) {
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
                    LOGW("Received STUN error from %s:%d", addr_str, addr.port);
                    break;
                default:
                    LOGW("Unknown STUN class from %s:%d", addr_str, addr.port);
                    break;
            }
            ret = 0;
        } else {
            // 非 STUN 数据包，可能是 DTLS 或 RTP
            LOGD("Non-STUN packet from %s:%d, size: %d", addr_str, addr.port, ret);
        }
    } else if (ret < 0 && ret != 0) {
        // 真正的错误（非超时）
        LOGE("socket_recv failed with error: %d", ret);
    }
    // ret == 0 是超时，这是正常的，不需要记录
    
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
    
    // 预先分配空间以避免重新分配导致指针失效
    // 考虑最坏情况：每个本地候选 * 每个远程候选 + peer-reflexive candidates
    size_t estimated_pairs = local_candidates_.size() * remote_candidates_.size() + 32;
    candidate_pairs_.reserve(estimated_pairs);
    LOGI("Reserved space for %zu candidate pairs", estimated_pairs);
    
    char local_addr_str[ADDRSTRLEN];
    char remote_addr_str[ADDRSTRLEN];
    
    // Create candidate pairs for matching address families
    for (size_t i = 0; i < local_candidates_.size(); i++) {
        for (size_t j = 0; j < remote_candidates_.size(); j++) {
            if (local_candidates_[i].get_addr().family == remote_candidates_[j].get_addr().family) {
                auto local_ptr = std::make_shared<IceCandidate>(local_candidates_[i]);
                auto remote_ptr = std::make_shared<IceCandidate>(remote_candidates_[j]);
                
                IceCandidatePair pair(local_ptr, remote_ptr);
                
                // 所有候选对初始状态都是FROZEN，由ICE协议决定检查顺序
                pair.set_state(IceCandidateState::FROZEN);
                
                candidate_pairs_.push_back(pair);
            }
        }
    }
    
    LOGI("Total candidate pairs: %d", static_cast<int>(candidate_pairs_.size()));
    
    // 如果有WAITING状态的候选对，立即开始检查
    for (auto& pair : candidate_pairs_) {
        if (pair.get_state() == IceCandidateState::WAITING) {
            nominated_pair_ = &pair;
            pair.set_state(IceCandidateState::INPROGRESS);
            LOGI("Starting connectivity check with prioritized pair");
            break;
        }
    }
}

int IceAgent::connectivity_check() {
    char addr_string[ADDRSTRLEN];
    uint8_t buf[1400];
    StunMessage msg;

    if (!nominated_pair_) {
        LOGE("No nominated pair for connectivity check");
        return -1;
    }
    
    // 如果已经是 SUCCEEDED，直接返回成功
    if (nominated_pair_->get_state() == IceCandidateState::SUCCEEDED) {
        selected_pair_ = nominated_pair_;
        return 0;
    }
    
    // 只有 INPROGRESS 状态才需要继续检查
    if (nominated_pair_->get_state() != IceCandidateState::INPROGRESS) {
        LOGW("Nominated pair in unexpected state: %d", static_cast<int>(nominated_pair_->get_state()));
        return -1;
    }

    std::memset(&msg, 0, sizeof(msg));

    if (nominated_pair_->get_conncheck() % CONNCHECK_PERIOD == 0) {
        Address remote_addr = nominated_pair_->get_remote()->get_addr();
        addr_to_string(&remote_addr, addr_string, sizeof(addr_string));
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
    // ICE 规范优先级：
    // 1. 优先使用 SUCCEEDED 状态的候选对（已验证连通性）
    // 2. 继续检查 INPROGRESS 的候选对
    // 3. 选择新的 FROZEN/WAITING 候选对开始检查
    
    // Step 1: 如果有 SUCCEEDED 的候选对，优先使用
    for (auto& pair : candidate_pairs_) {
        if (pair.get_state() == IceCandidateState::SUCCEEDED) {
            selected_pair_ = &pair;
            // 对于 CONTROLLED 角色，SUCCEEDED 的对应该被 nominated
            // 因为这表示已经收到了 Controlling 方的选择
            if (!nominated_pair_ || nominated_pair_->get_state() != IceCandidateState::SUCCEEDED) {
                nominated_pair_ = &pair;
                Address remote_addr = pair.get_remote()->get_addr();
                char addr_str[ADDRSTRLEN];
                addr_to_string(&remote_addr, addr_str, sizeof(addr_str));
                LOGI("Nominated SUCCEEDED pair for %s:%d", addr_str, remote_addr.port);
            }
            return 0;
        }
    }
    
    // Step 2: 检查 INPROGRESS 的候选对
    for (auto& pair : candidate_pairs_) {
        if (pair.get_state() == IceCandidateState::INPROGRESS) {
            pair.set_conncheck(pair.get_conncheck() + 1);
            if (pair.get_conncheck() < CONNCHECK_MAX) {
                // 继续等待连接检查
                return 0;
            }
            // 超时，标记为失败
            pair.set_state(IceCandidateState::FAILED);
            LOGD("Candidate pair timeout, marked as FAILED");
            
            // 如果这是 nominated_pair_，需要清除
            if (&pair == nominated_pair_) {
                nominated_pair_ = nullptr;
                LOGD("Cleared failed nominated pair");
            }
        }
    }
    
    // Step 3: 选择 WAITING 状态的候选对（优先级高于 FROZEN）
    for (auto& pair : candidate_pairs_) {
        if (pair.get_state() == IceCandidateState::WAITING) {
            nominated_pair_ = &pair;
            pair.set_conncheck(0);
            pair.set_state(IceCandidateState::INPROGRESS);
            Address remote_addr = pair.get_remote()->get_addr();
            char addr_str[ADDRSTRLEN];
            addr_to_string(&remote_addr, addr_str, sizeof(addr_str));
            LOGD("Starting check for WAITING pair with %s:%d", addr_str, remote_addr.port);
            return 0;
        }
    }
    
    // Step 4: 选择 FROZEN 状态的候选对
    for (auto& pair : candidate_pairs_) {
        if (pair.get_state() == IceCandidateState::FROZEN) {
            nominated_pair_ = &pair;
            pair.set_conncheck(0);
            pair.set_state(IceCandidateState::INPROGRESS);
            Address remote_addr = pair.get_remote()->get_addr();
            char addr_str[ADDRSTRLEN];
            addr_to_string(&remote_addr, addr_str, sizeof(addr_str));
            LOGD("Starting check for FROZEN pair with %s:%d", addr_str, remote_addr.port);
            return 0;
        }
    }
    
    // 所有候选对都失败或已检查
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