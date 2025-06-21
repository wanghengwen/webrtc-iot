#ifndef RTCP_HPP_
#define RTCP_HPP_

#include <cstdint>
#include <vector>
#include <memory>

#ifdef __BYTE_ORDER
#define __BIG_ENDIAN 4321
#define __LITTLE_ENDIAN 1234
#elif __APPLE__
#include <machine/endian.h>
#else
#include <endian.h>
#endif

namespace rtc {

enum class RtcpType : uint8_t {
    FIR = 192,
    SR = 200,
    RR = 201,
    SDES = 202,
    BYE = 203,
    APP = 204,
    RTPFB = 205,
    PSFB = 206,
    XR = 207
};

#pragma pack(push, 1)
struct RtcpHeader {
#if __BYTE_ORDER == __BIG_ENDIAN
    uint16_t version : 2;
    uint16_t padding : 1;
    uint16_t rc : 5;
    uint16_t type : 8;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t rc : 5;
    uint16_t padding : 1;
    uint16_t version : 2;
    uint16_t type : 8;
#endif
    uint16_t length : 16;
};

struct RtcpReportBlock {
    uint32_t ssrc;
    uint32_t flcnpl;
    uint32_t ehsnr;
    uint32_t jitter;
    uint32_t lsr;
    uint32_t dlsr;
};

struct RtcpRr {
    RtcpHeader header;
    uint32_t ssrc;
    RtcpReportBlock report_block[1];
};

struct RtcpFir {
    uint32_t ssrc;
    uint32_t seqnr;
};

struct RtcpFb {
    RtcpHeader header;
    uint32_t ssrc;
    uint32_t media;
    char fci[1];
};
#pragma pack(pop)

class RtcpPacket {
public:
    RtcpPacket() = default;
    virtual ~RtcpPacket() = default;
    
    // Copy and move operations
    RtcpPacket(const RtcpPacket&) = default;
    RtcpPacket& operator=(const RtcpPacket&) = default;
    RtcpPacket(RtcpPacket&&) = default;
    RtcpPacket& operator=(RtcpPacket&&) = default;
    
    virtual RtcpType get_type() const = 0;
    virtual std::vector<uint8_t> serialize() const = 0;
    virtual bool parse(const uint8_t* data, size_t size) = 0;
};

class RtcpPli : public RtcpPacket {
public:
    explicit RtcpPli(uint32_t ssrc = 0);
    ~RtcpPli() override = default;
    
    RtcpType get_type() const override { return RtcpType::PSFB; }
    std::vector<uint8_t> serialize() const override;
    bool parse(const uint8_t* data, size_t size) override;
    
    uint32_t get_ssrc() const { return ssrc_; }
    void set_ssrc(uint32_t ssrc) { ssrc_ = ssrc; }

private:
    uint32_t ssrc_;
};

class RtcpFirPacket : public RtcpPacket {
public:
    explicit RtcpFirPacket(int seq_nr = 0);
    ~RtcpFirPacket() override = default;
    
    RtcpType get_type() const override { return RtcpType::PSFB; }
    std::vector<uint8_t> serialize() const override;
    bool parse(const uint8_t* data, size_t size) override;
    
    int get_seq_nr() const { return seq_nr_; }
    void set_seq_nr(int seq_nr) { seq_nr_ = seq_nr; }

private:
    int seq_nr_;
};

class RtcpReceiverReport : public RtcpPacket {
public:
    RtcpReceiverReport();
    ~RtcpReceiverReport() override = default;
    
    RtcpType get_type() const override { return RtcpType::RR; }
    std::vector<uint8_t> serialize() const override;
    bool parse(const uint8_t* data, size_t size) override;
    
    const RtcpRr& get_report() const { return report_; }
    void set_report(const RtcpRr& report) { report_ = report; }

private:
    RtcpRr report_;
};

class RtcpProcessor {
public:
    RtcpProcessor() = default;
    ~RtcpProcessor() = default;
    
    // Copy and move operations
    RtcpProcessor(const RtcpProcessor&) = default;
    RtcpProcessor& operator=(const RtcpProcessor&) = default;
    RtcpProcessor(RtcpProcessor&&) = default;
    RtcpProcessor& operator=(RtcpProcessor&&) = default;
    
    static bool probe(const uint8_t* packet, size_t size);
    static std::unique_ptr<RtcpPacket> parse(const uint8_t* packet, size_t size);
    
    static std::vector<uint8_t> create_pli(uint32_t ssrc);
    static std::vector<uint8_t> create_fir(int& seq_nr);
    static rtc::RtcpRr parse_receiver_report(const uint8_t* packet);
};

} // namespace rtc

#endif  // RTCP_HPP_