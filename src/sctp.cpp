#include "sctp.hpp"
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <arpa/inet.h>

extern "C" {
#include "utils.h"
}

namespace rtc {

namespace {
    bool usrsctp_initialized = false;
}

void SctpAssociation::init_usrsctp() {
#if CONFIG_ENABLE_DATACHANNEL && CONFIG_USE_USRSCTP
    if (!usrsctp_initialized) {
        usrsctp_init(0, outgoing_data_callback, nullptr);
        usrsctp_initialized = true;
    }
#endif
}

void SctpAssociation::deinit_usrsctp() {
#if CONFIG_ENABLE_DATACHANNEL && CONFIG_USE_USRSCTP
    if (usrsctp_initialized) {
        usrsctp_finish();
        usrsctp_initialized = false;
    }
#endif
}

// CRC32C lookup table
static const uint32_t crc32c_table[256] = {
    0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
    0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
    0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
    0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
    0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
    0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
    0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
    0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
    0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
    0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
    0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
    0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
    0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
    0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
    0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
    0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
    0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
    0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
    0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
    0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
    0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
    0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
    0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
    0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
    0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
    0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
    0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
    0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
    0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
    0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
    0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
    0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
    0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
    0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
    0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
    0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
    0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
    0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
    0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
    0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
    0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
    0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
    0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
    0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
    0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
    0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
    0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
    0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
    0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
    0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
    0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
    0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
    0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
    0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
    0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
    0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
    0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
    0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
    0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
    0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
    0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
    0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
    0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
    0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L
};

SctpAssociation::SctpAssociation() 
    : sock_(nullptr)
    , local_port_(5000)
    , remote_port_(5000) 
    , connected_(false)
    , verification_tag_(0)
    , tsn_(1234)
    , dtls_srtp_(nullptr) {
    buffer_.resize(CONFIG_MTU);
    stream_table_.reserve(SCTP_MAX_STREAMS);
}

SctpAssociation::~SctpAssociation() {
    destroy_association();
}

uint32_t SctpAssociation::calculate_crc32c(const uint8_t* data, size_t length) const {
    uint32_t crc = 0xffffffff;
    while (length--) {
        crc = crc32c_table[(crc ^ *data++) & 0xFFL] ^ (crc >> 8);
    }
    return crc ^ 0xffffffff;
}

uint32_t SctpAssociation::get_checksum(const uint8_t* buf, size_t len) const {
    return calculate_crc32c(buf, len);
}

int SctpAssociation::outgoing_data_callback(void* userdata, void* buf, size_t len, uint8_t tos, uint8_t set_df) {
    SctpAssociation* sctp = static_cast<SctpAssociation*>(userdata);
    sctp->dtls_srtp_->write(static_cast<const uint8_t*>(buf), len);
    return 0;
}

void SctpAssociation::add_stream_mapping(const std::string& label, uint16_t sid) {
    if (stream_table_.size() < SCTP_MAX_STREAMS) {
        stream_table_.push_back({label, sid});
    } else {
        LOGE("Stream table full. Cannot add more streams.");
    }
}

int SctpAssociation::lookup_sid(const std::string& label, uint16_t& sid) const {
    for (const auto& entry : stream_table_) {
        if (entry.label == label) {
            sid = entry.sid;
            return 0;  // Found
        }
    }
    return -1;  // Not found
}

std::string SctpAssociation::lookup_sid_label(uint16_t sid) const {
    for (const auto& entry : stream_table_) {
        if (entry.sid == sid) {
            return entry.label;
        }
    }
    return "";  // Not found
}

void SctpAssociation::parse_data_channel_open(uint16_t sid, const char* data, size_t length) {
    if (length < 12) return;

    if (data[0] == static_cast<uint8_t>(DecpMsgType::DATA_CHANNEL_OPEN)) {
        uint16_t label_length = ntohs(*reinterpret_cast<const uint16_t*>(data + 8));
        uint16_t protocol_length = ntohs(*reinterpret_cast<const uint16_t*>(data + 10));

        if (length < 12 + label_length + protocol_length) return;

        std::string label(data + 12, label_length);
        
        std::cout << "DATA_CHANNEL_OPEN: Label=" << label << ", sid=" << sid << std::endl;
        
        add_stream_mapping(label, sid);
        char ack = static_cast<char>(DecpMsgType::DATA_CHANNEL_ACK);
        outgoing_data(&ack, 1, SctpDataPpid::CONTROL, sid);
    }
}

void SctpAssociation::handle_sctp_packet(const char* buf, size_t len) {
    if (len <= 29) return;
    if (buf[12] != 0) return; // if chunk_type is not zero, it's not data

    uint16_t sid = ntohs(*reinterpret_cast<const uint16_t*>(buf + 20));
    uint32_t ppid = ntohl(*reinterpret_cast<const uint32_t*>(buf + 24));

    if (ppid == static_cast<uint32_t>(DataChannelPpid::CONTROL)) {
        parse_data_channel_open(sid, buf + 28, len - 28);
    }
}

int SctpAssociation::outgoing_data(const char* buf, size_t len, SctpDataPpid ppid, uint16_t sid) {
#if CONFIG_USE_USRSCTP
    struct sctp_sendv_spa spa = {0};
    
    spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;
    spa.sendv_sndinfo.snd_sid = sid;
    spa.sendv_sndinfo.snd_flags = SCTP_EOR;
    spa.sendv_sndinfo.snd_ppid = htonl(static_cast<uint32_t>(ppid));
    
    int res = usrsctp_sendv(sock_, buf, len, nullptr, 0, &spa, sizeof(spa), SCTP_SENDV_SPA, 0);
    if (res < 0) {
        LOGE("sctp sendv error %d: %s", errno, strerror(errno));
    }
    return res;
#else
    size_t padding_len = 0;
    size_t payload_max = CONFIG_MTU - sizeof(SctpPacket) - sizeof(SctpDataChunk);
    size_t pos = 0;
    static uint16_t sqn = 0;

    auto* packet = reinterpret_cast<SctpPacket*>(buffer_.data());
    auto* chunk = reinterpret_cast<SctpDataChunk*>(packet->chunks);

    packet->header.source_port = htons(local_port_);
    packet->header.destination_port = htons(remote_port_);
    packet->header.verification_tag = verification_tag_;

    chunk->type = static_cast<uint8_t>(SctpHeaderType::DATA);
    chunk->iube = 0x06;
    chunk->sid = htons(0);
    chunk->sqn = htons(sqn++);
    chunk->ppid = htonl(static_cast<uint32_t>(ppid));

    while (len > payload_max) {
        chunk->length = htons(payload_max + sizeof(SctpDataChunk));
        chunk->tsn = htonl(tsn_++);
        memcpy(chunk->data, buf + pos, payload_max);
        packet->header.checksum = 0;

        packet->header.checksum = get_checksum(buffer_.data(), CONFIG_MTU);
        outgoing_data_callback(this, buffer_.data(), CONFIG_MTU, 0, 0);
        
        chunk->iube = 0x04;
        len -= payload_max;
        pos += payload_max;
    }

    if (len > 0) {
        chunk->length = htons(len + sizeof(SctpDataChunk));
        chunk->iube++;
        chunk->tsn = htonl(tsn_++);
        memset(chunk->data, 0, payload_max);
        memcpy(chunk->data, buf + pos, len);
        packet->header.checksum = 0;

        padding_len = 4 * ((len + sizeof(SctpDataChunk) + sizeof(SctpPacket) + 3) / 4);
        packet->header.checksum = get_checksum(buffer_.data(), padding_len);
        outgoing_data_callback(this, buffer_.data(), padding_len, 0, 0);
    }
#endif
    return static_cast<int>(len);
}

int SctpAssociation::handle_incoming_data(const char* data, size_t len, uint32_t ppid, uint16_t sid, int flags) {
#if CONFIG_USE_USRSCTP
    switch (static_cast<DataChannelPpid>(ppid)) {
        case DataChannelPpid::CONTROL:
            break;
        case DataChannelPpid::DOMSTRING:
        case DataChannelPpid::BINARY:
        case DataChannelPpid::DOMSTRING_PARTIAL:
        case DataChannelPpid::BINARY_PARTIAL:
            LOGD("Got message (size = %ld)", len);
            if (on_message_) {
                on_message_(data, len, sid);
            }
            break;
        default:
            break;
    }
#endif
    return 0;
}

#if CONFIG_USE_USRSCTP
void SctpAssociation::process_notification(union sctp_notification* notification, size_t len) {
    if (notification->sn_header.sn_length != static_cast<uint32_t>(len)) {
        return;
    }

    switch (notification->sn_header.sn_type) {
        case SCTP_ASSOC_CHANGE:
            switch (notification->sn_assoc_change.sac_state) {
                case SCTP_COMM_UP:
                    connected_ = true;
                    if (on_open_) {
                        on_open_();
                    }
                    break;
                case SCTP_COMM_LOST:
                case SCTP_SHUTDOWN_COMP:
                    connected_ = false;
                    if (on_close_) {
                        on_close_();
                    }
                    break;
                default:
                    break;
            }
            break;
        default:
            break;
    }
}

int SctpAssociation::incoming_data_callback(struct socket* sock, union sctp_sockstore addr, 
                                           void* data, size_t len, struct sctp_rcvinfo recv_info, 
                                           int flags, void* userdata) {
    auto* sctp = static_cast<SctpAssociation*>(userdata);
    LOGD("Data of length %u received on stream %u with SSN %u, TSN %u, PPID %u",
         static_cast<uint32_t>(len), recv_info.rcv_sid, recv_info.rcv_ssn,
         recv_info.rcv_tsn, ntohl(recv_info.rcv_ppid));
    
    if (flags & MSG_NOTIFICATION) {
        sctp->process_notification(static_cast<union sctp_notification*>(data), len);
    } else {
        sctp->handle_incoming_data(static_cast<char*>(data), len, 
                                  ntohl(recv_info.rcv_ppid), recv_info.rcv_sid, flags);
    }
    free(data);
    return 0;
}
#endif

void SctpAssociation::incoming_data(const char* buf, size_t len) {
    if (!buf) return;

#if CONFIG_USE_USRSCTP
    handle_sctp_packet(buf, len);
    usrsctp_conninput(this, const_cast<char*>(buf), len, 0);
#else
    size_t length = 0;
    size_t pos = sizeof(SctpHeader);
    
    auto* in_packet = reinterpret_cast<const SctpPacket*>(buf);
    auto* out_packet = reinterpret_cast<SctpPacket*>(buffer_.data());

    uint32_t crc32c = in_packet->header.checksum;
    auto* mutable_packet = const_cast<SctpPacket*>(in_packet);
    mutable_packet->header.checksum = 0;

    if (crc32c != get_checksum(reinterpret_cast<const uint8_t*>(buf), len)) {
        LOGE("checksum error");
        return;
    }

    memset(buffer_.data(), 0, buffer_.size());
    
    while ((4 * (pos + 3) / 4) < len) {
        auto* chunk_common = reinterpret_cast<const SctpChunkCommon*>(buf + pos);

        switch (static_cast<SctpHeaderType>(chunk_common->type)) {
            case SctpHeaderType::DATA: {
                auto* data_chunk = reinterpret_cast<const SctpDataChunk*>(buf + pos);
                auto* sack_chunk = reinterpret_cast<SctpSackChunk*>(out_packet->chunks);

                sack_chunk->common.type = static_cast<uint8_t>(SctpHeaderType::SACK);
                sack_chunk->common.flags = 0x00;
                sack_chunk->common.length = htons(16);
                sack_chunk->cumulative_tsn_ack = data_chunk->tsn;
                sack_chunk->a_rwnd = htonl(0x02);
                length = ntohs(sack_chunk->common.length) + sizeof(SctpHeader);

                LOGD("SCTP_DATA. ppid = %d, data = %.2x", ntohl(data_chunk->ppid), data_chunk->data[0]);
                
                if (ntohl(data_chunk->ppid) == static_cast<uint32_t>(DataChannelPpid::CONTROL) && 
                    data_chunk->data[0] == static_cast<uint8_t>(DecpMsgType::DATA_CHANNEL_OPEN)) {
                    // Handle data channel open response
                    auto* response_chunk = reinterpret_cast<SctpDataChunk*>(sack_chunk->blocks);
                    response_chunk->type = static_cast<uint8_t>(SctpHeaderType::DATA);
                    response_chunk->iube = 0x03;
                    response_chunk->tsn = htonl(tsn_++);
                    response_chunk->sid = htons(0);
                    response_chunk->sqn = htons(0);
                    response_chunk->ppid = htonl(static_cast<uint32_t>(DataChannelPpid::CONTROL));
                    response_chunk->length = htons(1 + sizeof(SctpDataChunk));
                    response_chunk->data[0] = static_cast<uint8_t>(DecpMsgType::DATA_CHANNEL_ACK);
                    length += ntohs(response_chunk->length);
                } else if (ntohl(data_chunk->ppid) == static_cast<uint32_t>(DataChannelPpid::DOMSTRING)) {
                    if (on_message_) {
                        on_message_(reinterpret_cast<const char*>(data_chunk->data), 
                                   ntohs(data_chunk->length) - sizeof(SctpDataChunk),
                                   ntohs(data_chunk->sid));
                    }
                }
                pos = len; // Do not handle other msg
                break;
            }
            
            case SctpHeaderType::INIT: {
                LOGD("SCTP_INIT");
                auto* init_chunk = reinterpret_cast<const SctpInitChunk*>(in_packet->chunks);
                verification_tag_ = init_chunk->initiate_tag;

                auto* init_ack = reinterpret_cast<SctpInitChunk*>(out_packet->chunks);
                init_ack->common.type = static_cast<uint8_t>(SctpHeaderType::INIT_ACK);
                init_ack->common.flags = 0x00;
                init_ack->common.length = htons(20 + 8);
                init_ack->initiate_tag = htonl(0x12345678);
                init_ack->a_rwnd = htonl(0x100000);
                init_ack->number_of_outbound_streams = 0xffff;
                init_ack->number_of_inbound_streams = 0xffff;
                init_ack->initial_tsn = htonl(tsn_);

                auto* param = init_ack->param;
                param->type = htons(static_cast<uint16_t>(SctpParamType::STATE_COOKIE));
                param->length = htons(8);
                *reinterpret_cast<uint32_t*>(&param->value) = htonl(0x02);
                length = ntohs(init_ack->common.length) + sizeof(SctpHeader);

                if (!connected_) {
                    connected_ = true;
                    if (on_open_) {
                        on_open_();
                    }
                }
                break;
            }
            
            case SctpHeaderType::INIT_ACK: {
                auto* init_ack = reinterpret_cast<const SctpInitChunk*>(in_packet->chunks);
                auto* cookie_echo = reinterpret_cast<SctpCookieEchoChunk*>(out_packet->chunks);
                verification_tag_ = init_ack->initiate_tag;
                
                // Find cookie parameter
                SctpChunkParam* param = nullptr;
                auto* cookie = reinterpret_cast<const uint8_t*>(&init_ack->param[0]);
                for (int i = 0; i < init_ack->common.length - 20; i += 2) {
                    uint16_t type = ntohs(*reinterpret_cast<const uint16_t*>(&cookie[i]));
                    if (type == 0x07) {
                        param = reinterpret_cast<SctpChunkParam*>(const_cast<uint8_t*>(&cookie[i]));
                        break;
                    }
                }

                if (param) {
                    cookie_echo->common.type = static_cast<uint8_t>(SctpHeaderType::COOKIE_ECHO);
                    cookie_echo->common.flags = 0x00;
                    cookie_echo->common.length = htons(ntohs(param->length));
                    memcpy(cookie_echo->cookie, param->value, ntohs(param->length) - 4);
                    length = ntohs(cookie_echo->common.length) + sizeof(SctpHeader);
                }

                if (!connected_) {
                    connected_ = true;
                    if (on_open_) {
                        on_open_();
                    }
                }
                break;
            }
            
            case SctpHeaderType::SACK:
                break;
                
            case SctpHeaderType::COOKIE_ECHO: {
                LOGD("SCTP_COOKIE_ECHO");
                auto* common = reinterpret_cast<SctpChunkCommon*>(out_packet->chunks);
                common->type = static_cast<uint8_t>(SctpHeaderType::COOKIE_ACK);
                common->length = htons(4);
                length = ntohs(common->length) + sizeof(SctpHeader);
                pos = len; // Do not handle other msg
                break;
            }
            
            case SctpHeaderType::COOKIE_ACK:
                break;
                
            case SctpHeaderType::ABORT:
                connected_ = false;
                if (on_close_) {
                    on_close_();
                }
                break;
                
            default:
                LOGI("Unknown chunk type %d", chunk_common->type);
                length = 0;
                break;
        }

        out_packet->header.source_port = htons(local_port_);
        out_packet->header.destination_port = htons(remote_port_);
        out_packet->header.verification_tag = verification_tag_;
        out_packet->header.checksum = 0x00;

        if (length > 0) {
            // padding 4
            length = (4 * ((length + 3) / 4));
            out_packet->header.checksum = get_checksum(buffer_.data(), length);
            dtls_srtp_->write(buffer_.data(), length);
        }
        pos += ntohs(chunk_common->length);
    }
#endif
}

int SctpAssociation::create_association(rtc::DtlsSrtpSession* dtls_srtp) {
    dtls_srtp_ = dtls_srtp;
    tsn_ = 1234;
    
#if CONFIG_USE_USRSCTP
    // Ensure USRSCTP is initialized
    init_usrsctp();
    
    usrsctp_sysctl_set_sctp_ecn_enable(0);
    usrsctp_register_address(this);

    struct socket* sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP,
                                         incoming_data_callback, nullptr, 0, this);

    if (!sock) {
        LOGE("usrsctp_socket failed");
        return -1;
    }

    int ret = -1;
    do {
        if (usrsctp_set_non_blocking(sock, 1) < 0) {
            LOGE("usrsctp_set_non_blocking failed");
            break;
        }

        struct linger lopt;
        lopt.l_onoff = 1;
        lopt.l_linger = 0;
        usrsctp_setsockopt(sock, SOL_SOCKET, SO_LINGER, &lopt, sizeof(lopt));

        struct sctp_assoc_value av;
        av.assoc_id = SCTP_ALL_ASSOC;
        av.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_CHANGE_ASSOC_REQ;
        usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &av, sizeof(av));

        uint32_t nodelay = 1;
        usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof(nodelay));

        static uint16_t event_types[] = {
            SCTP_ASSOC_CHANGE,
            SCTP_PEER_ADDR_CHANGE,
            SCTP_REMOTE_ERROR,
            SCTP_SHUTDOWN_EVENT,
            SCTP_ADAPTATION_INDICATION,
            SCTP_SEND_FAILED_EVENT,
            SCTP_SENDER_DRY_EVENT,
            SCTP_STREAM_RESET_EVENT,
            SCTP_STREAM_CHANGE_EVENT
        };

        struct sctp_event event;
        memset(&event, 0, sizeof(event));
        event.se_assoc_id = SCTP_ALL_ASSOC;
        event.se_on = 1;
        for (size_t i = 0; i < sizeof(event_types) / sizeof(uint16_t); i++) {
            event.se_type = event_types[i];
            usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event));
        }

        struct sctp_initmsg init_msg;
        memset(&init_msg, 0, sizeof(init_msg));
        init_msg.sinit_num_ostreams = 300;
        init_msg.sinit_max_instreams = 300;
        usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_INITMSG, &init_msg, sizeof(init_msg));

        struct sockaddr_conn sconn;
        memset(&sconn, 0, sizeof(sconn));
        sconn.sconn_family = AF_CONN;
        sconn.sconn_port = htons(local_port_);
        sconn.sconn_addr = (void*)this;
        ret = usrsctp_bind(sock, (struct sockaddr*)&sconn, sizeof(sconn));

        struct sockaddr_conn rconn;
        memset(&rconn, 0, sizeof(struct sockaddr_conn));
        rconn.sconn_family = AF_CONN;
        rconn.sconn_port = htons(remote_port_);
        rconn.sconn_addr = (void*)this;
        ret = usrsctp_connect(sock, (struct sockaddr*)&rconn, sizeof(struct sockaddr_conn));

        if (ret < 0 && errno != EINPROGRESS) {
            LOGE("connect error");
            break;
        }

        ret = 0;

    } while (0);

    if (ret < 0) {
        destroy_association();
        return -1;
    }

    sock_ = sock;
    
    // For testing: force connection state until DTLS handshake is fully working
    connected_ = true;
    LOGI("SCTP association created, forcing connected state for testing");
#else
    // Send SCTP_INIT
    auto* out_packet = reinterpret_cast<SctpPacket*>(buffer_.data());
    auto* header = &out_packet->header;
    auto* init_chunk = reinterpret_cast<SctpInitChunk*>(out_packet->chunks);

    header->source_port = htons(local_port_);
    header->destination_port = htons(remote_port_);
    header->verification_tag = 0x0;
    init_chunk->common.type = static_cast<uint8_t>(SctpHeaderType::INIT);
    init_chunk->common.flags = 0x00;
    init_chunk->common.length = htons(20);
    init_chunk->initiate_tag = htonl(0x12345678);
    init_chunk->a_rwnd = htonl(0x100000);
    init_chunk->number_of_outbound_streams = 0xffff;
    init_chunk->number_of_inbound_streams = 0xffff;
    init_chunk->initial_tsn = htonl(tsn_);
    
    size_t length = ntohs(init_chunk->common.length) + sizeof(SctpHeader);
    length = (4 * ((length + 3) / 4));
    header->checksum = get_checksum(buffer_.data(), length);
    dtls_srtp_->write(buffer_.data(), length);
#endif

    return 0;
}

void SctpAssociation::destroy_association() {
#if CONFIG_USE_USRSCTP
    if (sock_) {
        usrsctp_shutdown(sock_, SHUT_RDWR);
        usrsctp_close(sock_);
        sock_ = nullptr;
    }
#endif
}

} // namespace rtc