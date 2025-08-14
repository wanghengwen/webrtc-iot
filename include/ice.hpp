#ifndef ICE_HPP_
#define ICE_HPP_

#include <cstdint>
#include <string>
#include <memory>
#include "address.h"

#include "stun.h"

#define ICE_UFRAG_LENGTH 256
#define ICE_UPWD_LENGTH 256

namespace rtc {

enum class IceCandidateState {
    FROZEN = 0,
    WAITING,
    INPROGRESS,
    SUCCEEDED,
    FAILED
};

enum class IceCandidateType {
    HOST = 0,
    SRFLX,
    PRFLX,
    RELAY
};

class IceCandidate {
public:
    IceCandidate();
    IceCandidate(int foundation, IceCandidateType type, const Address& addr);
    ~IceCandidate() = default;
    
    // Copy and move operations
    IceCandidate(const IceCandidate&) = default;
    IceCandidate& operator=(const IceCandidate&) = default;
    IceCandidate(IceCandidate&&) = default;
    IceCandidate& operator=(IceCandidate&&) = default;
    
    // Getters
    const std::string& get_foundation() const { return foundation_; }
    int get_component() const { return component_; }
    uint32_t get_priority() const { return priority_; }
    const std::string& get_transport() const { return transport_; }
    IceCandidateType get_type() const { return type_; }
    IceCandidateState get_state() const { return state_; }
    const Address& get_addr() const { return addr_; }
    const Address& get_raddr() const { return raddr_; }
    
    // Setters
    void set_foundation(const std::string& foundation) { foundation_ = foundation; }
    void set_component(int component) { component_ = component; }
    void set_type(IceCandidateType type) { type_ = type; calculate_priority(); }
    void set_state(IceCandidateState state) { state_ = state; }
    void set_addr(const Address& addr) { addr_ = addr; calculate_priority(); }
    void set_raddr(const Address& raddr) { raddr_ = raddr; }
    void set_transport(const std::string& transport) { transport_ = transport; }
    
    // Methods
    void create(int foundation, IceCandidateType type, const Address& addr);
    std::string to_description() const;
    bool from_description(const std::string& description);
    Address get_local_address() const;
    
    // C compatibility methods removed for simplicity

private:
    std::string foundation_;
    int component_;
    uint32_t priority_;
    std::string transport_;
    IceCandidateType type_;
    IceCandidateState state_;
    Address addr_;
    Address raddr_;
    
    void calculate_priority();
    uint8_t get_type_preference() const;
    uint16_t get_local_preference() const;
};

class IceCandidatePair {
public:
    IceCandidatePair();
    IceCandidatePair(std::shared_ptr<IceCandidate> local, std::shared_ptr<IceCandidate> remote);
    ~IceCandidatePair() = default;
    
    // Copy and move operations
    IceCandidatePair(const IceCandidatePair&) = default;
    IceCandidatePair& operator=(const IceCandidatePair&) = default;
    IceCandidatePair(IceCandidatePair&&) = default;
    IceCandidatePair& operator=(IceCandidatePair&&) = default;
    
    // Getters
    IceCandidateState get_state() const { return state_; }
    std::shared_ptr<IceCandidate> get_local() const { return local_; }
    std::shared_ptr<IceCandidate> get_remote() const { return remote_; }
    int get_conncheck() const { return conncheck_; }
    uint64_t get_priority() const { return priority_; }
    
    // Setters
    void set_state(IceCandidateState state) { state_ = state; }
    void set_local(std::shared_ptr<IceCandidate> local) { local_ = local; calculate_priority(); }
    void set_remote(std::shared_ptr<IceCandidate> remote) { remote_ = remote; calculate_priority(); }
    void set_conncheck(int conncheck) { conncheck_ = conncheck; }
    
private:
    IceCandidateState state_;
    std::shared_ptr<IceCandidate> local_;
    std::shared_ptr<IceCandidate> remote_;
    int conncheck_;
    uint64_t priority_;
    
    void calculate_priority();
};

} // namespace rtc

#endif  // ICE_HPP_