#include "sdp.hpp"
#include <cstdio>
#include <cstring>
#include <cstdarg>

namespace rtc {

SdpBuilder::SdpBuilder() {
    sdp_.reserve(CONFIG_SDP_BUFFER_SIZE);
}

void SdpBuilder::append(const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    
    sdp_ += buffer;
    ensure_newline();
    
    va_end(args);
}

void SdpBuilder::ensure_newline() {
    if (!sdp_.empty() && sdp_.back() != '\n') {
        sdp_ += "\r\n";
    }
}

void SdpBuilder::reset() {
    sdp_.clear();
}

void SdpBuilder::append_h264(uint32_t ssrc) {
    append("m=video 9 UDP/TLS/RTP/SAVPF 96");
    append("c=IN IP4 0.0.0.0");
    append("a=rtcp-fb:96 nack");
    append("a=rtcp-fb:96 nack pli");
    append("a=fmtp:96 profile-level-id=42e01f;level-asymmetry-allowed=1");
    append("a=rtpmap:96 H264/90000");
    append("a=ssrc:%u cname:webrtc-h264", ssrc);
    append("a=sendrecv");
    append("a=mid:video");
    append("a=rtcp-mux");
}

void SdpBuilder::append_pcma(uint32_t ssrc) {
    append("m=audio 9 UDP/TLS/RTP/SAVP 8");
    append("c=IN IP4 0.0.0.0");
    append("a=rtpmap:8 PCMA/8000");
    append("a=ssrc:%u cname:webrtc-pcma", ssrc);
    append("a=sendrecv");
    append("a=mid:audio");
    append("a=rtcp-mux");
}

void SdpBuilder::append_pcmu(uint32_t ssrc) {
    append("m=audio 9 UDP/TLS/RTP/SAVP 0");
    append("c=IN IP4 0.0.0.0");
    append("a=rtpmap:0 PCMU/8000");
    append("a=ssrc:%u cname:webrtc-pcmu", ssrc);
    append("a=sendrecv");
    append("a=mid:audio");
    append("a=rtcp-mux");
}

void SdpBuilder::append_opus(uint32_t ssrc) {
    append("m=audio 9 UDP/TLS/RTP/SAVP 111");
    append("c=IN IP4 0.0.0.0");
    append("a=rtpmap:111 opus/48000/2");
    append("a=ssrc:%u cname:webrtc-opus", ssrc);
    append("a=sendrecv");
    append("a=mid:audio");
    append("a=rtcp-mux");
}

void SdpBuilder::append_datachannel() {
    append("m=application 50712 UDP/DTLS/SCTP webrtc-datachannel");
    append("c=IN IP4 0.0.0.0");
    append("a=mid:datachannel");
    append("a=sctp-port:5000");
    append("a=max-message-size:262144");
}

void SdpBuilder::create(bool has_video, bool has_audio, bool has_datachannel) {
    append("v=0");
    append("o=- 1495799811084970 1495799811084970 IN IP4 0.0.0.0");
    append("s=-");
    append("t=0 0");
    append("a=msid-semantic: iot");
    
#if ICE_LITE
    append("a=ice-lite");
#endif

    std::string bundle = "a=group:BUNDLE";
    
    if (has_video) {
        bundle += " video";
    }
    
    if (has_audio) {
        bundle += " audio";
    }
    
    if (has_datachannel) {
        bundle += " datachannel";
    }
    
    append(bundle.c_str());
}

} // namespace rtc

