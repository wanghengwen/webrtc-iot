#ifndef SCTP_HPP_
#define SCTP_HPP_

#include <cstdint>
#include <vector>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include "config.h"

#include "dtls_srtp.hpp"

#if CONFIG_USE_USRSCTP
extern "C" {
#include <usrsctp.h>
}
#endif

namespace rtc {

enum class DecpMsgType : uint8_t {
    DATA_CHANNEL_OPEN = 0x03,
    DATA_CHANNEL_ACK = 0x02
};

enum class DataChannelPpid : uint32_t {
    CONTROL = 50,
    DOMSTRING = 51,
    BINARY_PARTIAL = 52,
    BINARY = 53,
    DOMSTRING_PARTIAL = 54
};

enum class SctpDataPpid : uint32_t {
    CONTROL = 50,
    STRING = 51,
    BINARY = 53,
    STRING_EMPTY = 56,
    BINARY_EMPTY = 57
};

#if !CONFIG_USE_USRSCTP

enum class SctpParamType : uint16_t {
    STATE_COOKIE = 7
};

enum class SctpHeaderType : uint8_t {
    DATA = 0,
    INIT = 1,
    INIT_ACK = 2,
    SACK = 3,
    HEARTBEAT = 4,
    HEARTBEAT_ACK = 5,
    ABORT = 6,
    SHUTDOWN = 7,
    SHUTDOWN_ACK = 8,
    ERROR = 9,
    COOKIE_ECHO = 10,
    COOKIE_ACK = 11,
    ECNE = 12,
    CWR = 13,
    SHUTDOWN_COMPLETE = 14,
    AUTH = 15,
    ASCONF_ACK = 128,
    ASCONF = 130,
    FORWARD_TSN = 192
};

#pragma pack(push, 1)
struct SctpChunkParam {
    uint16_t type;
    uint16_t length;
    uint8_t value[0];
};

struct SctpChunkCommon {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
};

struct SctpForwardTsnChunk {
    SctpChunkCommon common;
    uint32_t new_cumulative_tsn;
    uint16_t stream_number;
    uint16_t stream_sequence_number;
};

struct SctpHeader {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t verification_tag;
    uint32_t checksum;
};

struct SctpPacket {
    SctpHeader header;
    uint8_t chunks[0];
};

struct SctpSackChunk {
    SctpChunkCommon common;
    uint32_t cumulative_tsn_ack;
    uint32_t a_rwnd;
    uint16_t number_of_gap_ack_blocks;
    uint16_t number_of_dup_tsns;
    uint8_t blocks[0];
};

struct SctpDataChunk {
    uint8_t type;
    uint8_t iube;
    uint16_t length;
    uint32_t tsn;
    uint16_t sid;
    uint16_t sqn;
    uint32_t ppid;
    uint8_t data[0];
};

struct SctpInitChunk {
    SctpChunkCommon common;
    uint32_t initiate_tag;
    uint32_t a_rwnd;
    uint16_t number_of_outbound_streams;
    uint16_t number_of_inbound_streams;
    uint32_t initial_tsn;
    SctpChunkParam param[0];
};

struct SctpCookieEchoChunk {
    SctpChunkCommon common;
    uint8_t cookie[0];
};
#pragma pack(pop)

#endif

struct SctpStreamEntry {
    std::string label;
    uint16_t sid;
};

using SctpOnMessageCallback = std::function<void(const char* msg, size_t len, uint16_t sid)>;
using SctpOnOpenCallback = std::function<void()>;
using SctpOnCloseCallback = std::function<void()>;

class SctpAssociation {
public:
    static constexpr int SCTP_MAX_STREAMS = 5;
    
    // Library initialization (call once per process)
    static void init_usrsctp();
    static void deinit_usrsctp();
    
    SctpAssociation();
    ~SctpAssociation();
    
    // Copy and move operations
    SctpAssociation(const SctpAssociation&) = delete;
    SctpAssociation& operator=(const SctpAssociation&) = delete;
    SctpAssociation(SctpAssociation&&) = default;
    SctpAssociation& operator=(SctpAssociation&&) = default;
    
    // Setup and teardown
    int create_association(rtc::DtlsSrtpSession* dtls_srtp);
    void destroy_association();
    
    // Connection status
    bool is_connected() const { return connected_; }
    
    // Data handling
    void incoming_data(const char* buf, size_t len);
    int outgoing_data(const char* buf, size_t len, SctpDataPpid ppid, uint16_t sid);
    
    // Stream management
    void add_stream_mapping(const std::string& label, uint16_t sid);
    int lookup_sid(const std::string& label, uint16_t& sid) const;
    std::string lookup_sid_label(uint16_t sid) const;
    
    // Callbacks
    void set_on_message(SctpOnMessageCallback callback) { on_message_ = callback; }
    void set_on_open(SctpOnOpenCallback callback) { on_open_ = callback; }
    void set_on_close(SctpOnCloseCallback callback) { on_close_ = callback; }
    
private:
    struct socket* sock_;
    
    int local_port_;
    int remote_port_;
    bool connected_;
    uint32_t verification_tag_;
    uint32_t tsn_;
    rtc::DtlsSrtpSession* dtls_srtp_;
    
    std::vector<SctpStreamEntry> stream_table_;
    
    SctpOnMessageCallback on_message_;
    SctpOnOpenCallback on_open_;
    SctpOnCloseCallback on_close_;
    
    std::vector<uint8_t> buffer_;
    
    // Internal methods
    uint32_t calculate_crc32c(const uint8_t* data, size_t length) const;
    uint32_t get_checksum(const uint8_t* buf, size_t len) const;
    void parse_data_channel_open(uint16_t sid, const char* data, size_t length);
    void handle_sctp_packet(const char* buf, size_t len);
    int handle_incoming_data(const char* data, size_t len, uint32_t ppid, uint16_t sid, int flags);
    
#if CONFIG_USE_USRSCTP
    void process_notification(union sctp_notification* notification, size_t len);
    static int incoming_data_callback(struct socket* sock, union sctp_sockstore addr, 
                                     void* data, size_t len, struct sctp_rcvinfo recv_info, 
                                     int flags, void* userdata);
#endif
    
    static int outgoing_data_callback(void* userdata, void* buf, size_t len, uint8_t tos, uint8_t set_df);
};

} // namespace rtc

#endif  // SCTP_HPP_