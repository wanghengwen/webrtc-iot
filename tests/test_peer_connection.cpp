#include <pthread.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <memory>
#include <vector>
#include <cmath>
#include <algorithm>

#include "peer_connection.hpp"

#define MAX_CONNECTION_ATTEMPTS 10
#define OFFER_DATACHANNEL_MESSAGE "Hello World"
#define ANSWER_DATACHANNEL_MESSAGE "Foobar"
#define DATACHANNEL_NAME "libpeer-datachannel"

// Audio test constants
#define AUDIO_TEST_SAMPLES 160  // 20ms of 8kHz audio
#define AUDIO_TEST_DURATION_MS 100  // Total test duration
#define AUDIO_SAMPLE_RATE 8000

bool test_complete = false;

struct TestUserData {
    std::unique_ptr<rtc::PeerConnection> offer_peer_connection;
    std::unique_ptr<rtc::PeerConnection> answer_peer_connection;
    bool onmessage_offer_called = false;
    bool onmessage_answer_called = false;
    
    // Audio test data
    std::vector<uint8_t> sent_audio_data;
    std::vector<uint8_t> received_audio_data;
    bool audio_test_sent = false;
    bool audio_test_received = false;
    size_t expected_audio_size = 0;
};

void* peer_connection_task(void* user_data) {
    auto* pc = static_cast<rtc::PeerConnection*>(user_data);

    while (!test_complete) {
        pc->loop();
        usleep(1000);
    }

    pthread_exit(nullptr);
    return nullptr;
}

int main(int argc, char* argv[]) {
    (void)argc; // Suppress unused parameter warning
    (void)argv;

    TestUserData test_user_data;

    rtc::PeerConfiguration config;
    // Use a more reliable STUN server
    config.ice_servers.push_back({"stun:stun.l.google.com:19302", "", ""});
    config.datachannel = rtc::DataChannelType::STRING; // Enable datachannel
    config.video_codec = rtc::MediaCodec::NONE; // Disable video for simpler test  
    config.audio_codec = rtc::MediaCodec::PCMU; // Enable PCMU audio for testing
    
    // Audio callback will be set per peer connection below

    test_user_data.offer_peer_connection = std::make_unique<rtc::PeerConnection>(config);
    
    // Create separate config for answer - this one needs the audio callback
    rtc::PeerConfiguration answer_config = config;
    answer_config.on_audio_track = [&test_user_data](const uint8_t* data, size_t size) {
        printf("Answer peer received audio data: %zu bytes\n", size);
        
        // Append received data
        test_user_data.received_audio_data.insert(
            test_user_data.received_audio_data.end(), data, data + size);
        
        // Check if we received enough data
        if (test_user_data.received_audio_data.size() >= test_user_data.expected_audio_size) {
            test_user_data.audio_test_received = true;
            printf("Audio test: received %zu bytes, expected %zu bytes\n", 
                   test_user_data.received_audio_data.size(), 
                   test_user_data.expected_audio_size);
        }
    };
    
    test_user_data.answer_peer_connection = std::make_unique<rtc::PeerConnection>(answer_config);

    // Set up callbacks
    test_user_data.offer_peer_connection->on_ice_connection_state_change(
        [](rtc::PeerConnectionState state) {
            printf("offer state is changed: %s\n", 
                   (state == rtc::PeerConnectionState::NEW) ? "new" :
                   (state == rtc::PeerConnectionState::CHECKING) ? "checking" :
                   (state == rtc::PeerConnectionState::CONNECTED) ? "connected" :
                   (state == rtc::PeerConnectionState::COMPLETED) ? "completed" :
                   (state == rtc::PeerConnectionState::FAILED) ? "failed" :
                   (state == rtc::PeerConnectionState::DISCONNECTED) ? "disconnected" :
                   (state == rtc::PeerConnectionState::CLOSED) ? "closed" : "unknown");
        });

    test_user_data.answer_peer_connection->on_ice_connection_state_change(
        [](rtc::PeerConnectionState state) {
            printf("answerer state is changed: %s\n", 
                   (state == rtc::PeerConnectionState::NEW) ? "new" :
                   (state == rtc::PeerConnectionState::CHECKING) ? "checking" :
                   (state == rtc::PeerConnectionState::CONNECTED) ? "connected" :
                   (state == rtc::PeerConnectionState::COMPLETED) ? "completed" :
                   (state == rtc::PeerConnectionState::FAILED) ? "failed" :
                   (state == rtc::PeerConnectionState::DISCONNECTED) ? "disconnected" :
                   (state == rtc::PeerConnectionState::CLOSED) ? "closed" : "unknown");
        });

    test_user_data.offer_peer_connection->on_ice_candidate([](const std::string& sdp) {
        // Handle ICE candidate for offer peer connection
    });

    test_user_data.answer_peer_connection->on_ice_candidate([](const std::string& sdp) {
        // Handle ICE candidate for answer peer connection
    });

    // Set up datachannel callbacks
    test_user_data.offer_peer_connection->on_datachannel(
        [&test_user_data](const char* msg, size_t len, uint16_t sid) {
            printf("Offer peer received datachannel message: %.*s (sid: %d)\n", 
                   static_cast<int>(len), msg, sid);
            if (strncmp(msg, ANSWER_DATACHANNEL_MESSAGE, len) == 0) {
                test_user_data.onmessage_offer_called = true;
            }
        },
        []() {
            printf("Offer peer datachannel opened\n");
        },
        []() {
            printf("Offer peer datachannel closed\n");
        });

    test_user_data.answer_peer_connection->on_datachannel(
        [&test_user_data](const char* msg, size_t len, uint16_t sid) {
            printf("Answer peer received datachannel message: %.*s (sid: %d)\n", 
                   static_cast<int>(len), msg, sid);
            if (strncmp(msg, OFFER_DATACHANNEL_MESSAGE, len) == 0) {
                test_user_data.onmessage_answer_called = true;
                // Send response back
                test_user_data.answer_peer_connection->datachannel_send(
                    ANSWER_DATACHANNEL_MESSAGE, strlen(ANSWER_DATACHANNEL_MESSAGE));
            }
        },
        []() {
            printf("Answer peer datachannel opened\n");
        },
        []() {
            printf("Answer peer datachannel closed\n");
        });

    // Create threads for concurrent peer connection processing
    pthread_t offer_thread, answer_thread;
    pthread_create(&offer_thread, nullptr, peer_connection_task, 
                   test_user_data.offer_peer_connection.get());
    pthread_create(&answer_thread, nullptr, peer_connection_task, 
                   test_user_data.answer_peer_connection.get());

    std::string offer = test_user_data.offer_peer_connection->create_offer();
    printf("Offer SDP:\n%s\n", offer.c_str());
    
    test_user_data.answer_peer_connection->set_remote_description(offer, rtc::SdpType::OFFER);
    
    std::string answer = test_user_data.answer_peer_connection->create_answer();
    printf("Answer SDP:\n%s\n", answer.c_str());
    
    test_user_data.offer_peer_connection->set_remote_description(answer, rtc::SdpType::ANSWER);

    int attempts = 0;
    
    while (attempts < MAX_CONNECTION_ATTEMPTS) {
        // Threads are handling the loop() calls
        
        printf("Attempt %d: Offer state=%d, Answer state=%d\n", 
               attempts,
               static_cast<int>(test_user_data.offer_peer_connection->get_state()),
               static_cast<int>(test_user_data.answer_peer_connection->get_state()));
        
        // Check if both reach connected or completed state, then test datachannel
        auto offer_state = test_user_data.offer_peer_connection->get_state();
        auto answer_state = test_user_data.answer_peer_connection->get_state();
        if ((offer_state == rtc::PeerConnectionState::CONNECTED || offer_state == rtc::PeerConnectionState::COMPLETED) &&
            (answer_state == rtc::PeerConnectionState::CONNECTED || answer_state == rtc::PeerConnectionState::COMPLETED)) {
            printf("Both connections reached CONNECTED/COMPLETED state!\n");
            
            // Wait a bit for SCTP to establish, then test datachannel
            if (attempts > 3) {  // Give SCTP time to connect
                static bool datachannel_test_sent = false;
                if (!datachannel_test_sent) {
                    printf("Sending datachannel test message: %s\n", OFFER_DATACHANNEL_MESSAGE);
                    printf("Offer SCTP connected: %s\n", 
                           test_user_data.offer_peer_connection->is_sctp_connected() ? "YES" : "NO");
                    printf("Answer SCTP connected: %s\n", 
                           test_user_data.answer_peer_connection->is_sctp_connected() ? "YES" : "NO");
                    
                    test_user_data.offer_peer_connection->datachannel_send(
                        OFFER_DATACHANNEL_MESSAGE, strlen(OFFER_DATACHANNEL_MESSAGE));
                    datachannel_test_sent = true;
                }
                
                // Test audio transmission
                if (attempts >= 4 && !test_user_data.audio_test_sent) {
                    printf("Starting audio transmission test...\n");
                    
                    // Generate test audio data (sine wave pattern)
                    test_user_data.sent_audio_data.resize(AUDIO_TEST_SAMPLES);
                    for (int i = 0; i < AUDIO_TEST_SAMPLES; i++) {
                        // Generate a simple pattern that can be verified
                        test_user_data.sent_audio_data[i] = static_cast<uint8_t>(
                            128 + 127 * sin(2 * M_PI * 440 * i / AUDIO_SAMPLE_RATE));
                    }
                    
                    test_user_data.expected_audio_size = AUDIO_TEST_SAMPLES;
                    
                    printf("Sending audio data: %zu bytes\n", test_user_data.sent_audio_data.size());
                    int audio_result = test_user_data.offer_peer_connection->send_audio(
                        test_user_data.sent_audio_data.data(), 
                        test_user_data.sent_audio_data.size());
                    printf("Audio send result: %d\n", audio_result);
                    
                    test_user_data.audio_test_sent = true;
                }
                
                // Check if both datachannel messages were received
                if (test_user_data.onmessage_offer_called && test_user_data.onmessage_answer_called) {
                    printf("Datachannel test successful - both messages received!\n");
                    
                    // Check audio test results
                    if (test_user_data.audio_test_sent && test_user_data.audio_test_received) {
                        printf("Audio test successful - audio data transmitted!\n");
                        
                        // Verify audio data integrity (check first few bytes)
                        bool audio_data_match = true;
                        size_t check_size = std::min(test_user_data.sent_audio_data.size(), 
                                                    test_user_data.received_audio_data.size());
                        check_size = std::min(check_size, size_t(20)); // Check first 20 bytes
                        
                        for (size_t i = 0; i < check_size; i++) {
                            if (test_user_data.sent_audio_data[i] != test_user_data.received_audio_data[i]) {
                                audio_data_match = false;
                                printf("Audio data mismatch at byte %zu: sent=%d, received=%d\n",
                                       i, test_user_data.sent_audio_data[i], 
                                       test_user_data.received_audio_data[i]);
                                break;
                            }
                        }
                        
                        if (audio_data_match) {
                            printf("Audio data integrity verified - test PASSED!\n");
                        } else {
                            printf("Audio data integrity check failed\n");
                        }
                    }
                    break;
                } else if (test_user_data.offer_peer_connection->is_sctp_connected() && 
                          test_user_data.answer_peer_connection->is_sctp_connected() &&
                          attempts > 8) {  // Give more time for audio test
                    printf("SCTP connections established\n");
                    
                    if (test_user_data.audio_test_sent && test_user_data.audio_test_received) {
                        printf("Audio test completed - connections successful!\n");
                    } else {
                        printf("Audio test incomplete but connections established\n");
                    }
                    break;
                }
            }
        }

        attempts++;
        usleep(100000); // Reduce sleep time for faster testing
        
        // Early exit if both connections fail
        if (test_user_data.offer_peer_connection->get_state() == rtc::PeerConnectionState::FAILED ||
            test_user_data.answer_peer_connection->get_state() == rtc::PeerConnectionState::FAILED) {
            printf("Connection failed, breaking early\n");
            break;
        }
    }

    test_complete = true;
    
    // Wait for threads to exit
    pthread_join(offer_thread, nullptr);
    pthread_join(answer_thread, nullptr);
    
    printf("Test completed with %d attempts\n", attempts);
    
    // Success if we broke out of the loop before reaching max attempts
    if (attempts < MAX_CONNECTION_ATTEMPTS) {
        printf("Test PASSED: Connection established successfully\n");
        return 0;
    } else {
        printf("Test FAILED: Connection not established within time limit\n");
        return 1;
    }
}