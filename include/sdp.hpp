#ifndef SDP_HPP_
#define SDP_HPP_

#include <string>
#include <cstdarg>
#include "config.h"

#ifndef ICE_LITE
#define ICE_LITE 0
#endif

namespace rtc {

class SdpBuilder {
public:
    SdpBuilder();
    ~SdpBuilder() = default;
    
    // Copy and move operations
    SdpBuilder(const SdpBuilder&) = default;
    SdpBuilder& operator=(const SdpBuilder&) = default;
    SdpBuilder(SdpBuilder&&) = default;
    SdpBuilder& operator=(SdpBuilder&&) = default;
    
    // Main SDP building methods
    void create(bool has_video, bool has_audio, bool has_datachannel);
    void append(const char* format, ...);
    void reset();
    
    // Media-specific append methods
    void append_h264(uint32_t ssrc = 1);
    void append_pcma(uint32_t ssrc = 4);
    void append_pcmu(uint32_t ssrc = 5);
    void append_opus(uint32_t ssrc = 6);
    void append_datachannel();
    
    // Get the built SDP
    const std::string& get_sdp() const { return sdp_; }
    const char* c_str() const { return sdp_.c_str(); }
    
    // Direct access for C compatibility
    char* data() { return const_cast<char*>(sdp_.c_str()); }
    size_t size() const { return sdp_.size(); }
    size_t capacity() const { return CONFIG_SDP_BUFFER_SIZE; }

private:
    std::string sdp_;
    
    void ensure_newline();
};

} // namespace rtc

#endif  // SDP_HPP_