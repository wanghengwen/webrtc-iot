#ifndef AGENT_HPP_
#define AGENT_HPP_

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <array>

#include "base64.h"
#include "socket.h"
#include "stun.h"
#include "ports.h"

#include "ice.hpp"

namespace rtc {


#ifndef AGENT_MAX_CANDIDATES
#define AGENT_MAX_CANDIDATES 10
#endif

#ifndef AGENT_MAX_CANDIDATE_PAIRS
#define AGENT_MAX_CANDIDATE_PAIRS 100
#endif

enum class AgentState {
    GATHERING_ENDED = 0,
    GATHERING_STARTED,
    GATHERING_COMPLETED
};

enum class AgentMode {
    CONTROLLED = 0,
    CONTROLLING
};

class IceAgent {
public:
    IceAgent();
    ~IceAgent();
    
    // Copy and move operations
    IceAgent(const IceAgent&) = delete;
    IceAgent& operator=(const IceAgent&) = delete;
    IceAgent(IceAgent&&) = default;
    IceAgent& operator=(IceAgent&&) = default;
    
    // Lifecycle management
    int create();
    void destroy();
    
    // Candidate management
    void gather_candidate(const std::string& urls, const std::string& username, const std::string& credential);
    void clear_candidates();
    void update_candidate_pairs();
    int add_ice_candidate(const std::string& ice_candidate);
    
    // ICE credential management
    void create_ice_credential();
    
    // Description management
    void get_local_description(std::string& description) const;
    void set_remote_description(const std::string& description);
    
    // Data transmission
    int send(const uint8_t* buf, int len);
    int recv(uint8_t* buf, int len);
    
    // Connectivity
    int select_candidate_pair();
    int connectivity_check();
    
    // Getters
    AgentState get_state() const { return state_; }
    AgentMode get_mode() const { return mode_; }
    const std::string& get_local_ufrag() const { return local_ufrag_; }
    const std::string& get_local_upwd() const { return local_upwd_; }
    const std::string& get_remote_ufrag() const { return remote_ufrag_; }
    const std::string& get_remote_upwd() const { return remote_upwd_; }
    uint64_t get_binding_request_time() const { return binding_request_time_; }
    
    // Setters
    void set_mode(AgentMode mode) { mode_ = mode; }
    
    // Get remote address from nominated or selected pair
    Address* get_nominated_remote_addr() const {
        // Try nominated pair first, then selected pair
        auto* pair = nominated_pair_ ? nominated_pair_ : selected_pair_;
        if (pair && pair->get_remote()) {
            return const_cast<Address*>(&pair->get_remote()->get_addr());
        }
        return nullptr;
    }

private:
    // ICE credentials
    std::string remote_ufrag_;
    std::string remote_upwd_;
    std::string local_ufrag_;
    std::string local_upwd_;
    
    // Candidates
    std::vector<rtc::IceCandidate> local_candidates_;
    std::vector<rtc::IceCandidate> remote_candidates_;
    
    // Network sockets
    std::array<UdpSocket, 2> udp_sockets_;
    
    // Host address information
    Address host_addr_;
    bool b_host_addr_;
    uint64_t binding_request_time_;
    AgentState state_;
    AgentMode mode_;
    
    // Candidate pairs
    std::vector<rtc::IceCandidatePair> candidate_pairs_;
    rtc::IceCandidatePair* selected_pair_;
    rtc::IceCandidatePair* nominated_pair_;
    
    // Connection state
    bool use_candidate_;
    std::array<uint32_t, 3> transaction_id_;
    
    // Private helper methods
    int socket_recv(Address* addr, uint8_t* buf, int len);
    int socket_recv_attempts(Address* addr, uint8_t* buf, int len, int maxtimes);
    int socket_send(const Address* addr, const uint8_t* buf, int len);
    
    // Candidate creation methods
    int create_host_addr();
    int create_stun_addr(const Address* serv_addr);
    int create_turn_addr(const Address* serv_addr, const std::string& username, const std::string& credential);
    
    // STUN related methods
    void create_binding_response(StunMessage* msg, const Address* addr);
    void create_binding_request(StunMessage* msg);
    void process_stun_request(StunMessage* stun_msg, const Address* addr);
    void process_stun_response(StunMessage* stun_msg);
    
    static constexpr int POLL_TIMEOUT = 5;   //5ms
    static constexpr int CONNCHECK_MAX = 1000;
    static constexpr int CONNCHECK_PERIOD = 100;
    static constexpr int STUN_RECV_MAXTIMES = 1000;
};

} // namespace rtc

#endif  // AGENT_HPP_