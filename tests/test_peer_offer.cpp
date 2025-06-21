#include <pthread.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <memory>
#include <vector>
#include <cmath>
#include <algorithm>
#include <iostream>
#include <string>
#include <random>
#include <chrono>
#include <map>

#include "peer_connection.hpp"

extern "C" {
#include "base64.h"
}

#define MAX_CONNECTION_ATTEMPTS 1200
#define AUDIO_TEST_SAMPLES 160  // 20ms of 8kHz audio
#define AUDIO_SAMPLE_RATE 8000
#define AUDIO_SEND_COUNT 1000    // Number of audio packets to send
#define AUDIO_SEND_INTERVAL_MS 20  // Interval between sends

bool test_complete = false;
bool connection_established = false;

struct TestUserData {
    std::unique_ptr<rtc::PeerConnection> peer_connection;
    std::map<uint8_t, std::vector<uint8_t>> sent_audio_packets; // Map of N -> packet data
    std::vector<uint8_t> received_audio_data;
    int audio_packets_sent = 0;
    int audio_packets_received = 0;
    int audio_packets_verified = 0;
    std::vector<std::string> ice_candidates;
    bool gathering_complete = false;
    std::chrono::steady_clock::time_point last_send_time;
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<> dis;
    
    TestUserData() : gen(rd()), dis(0, 255) {}
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
    (void)argc;
    (void)argv;

    // Enable debug logging
    setenv("LIBPEER_LOG_LEVEL", "DEBUG", 1);

    TestUserData test_user_data;

    rtc::PeerConfiguration config;
    config.ice_servers.push_back({"stun:139.224.197.48:39870", "", ""});
    config.datachannel = rtc::DataChannelType::NONE; // Disable datachannel
    config.video_codec = rtc::MediaCodec::NONE; // Disable video
    config.audio_codec = rtc::MediaCodec::PCMA; // Enable PCMA audio only

    // Set up audio callback to receive data
    config.on_audio_track = [&test_user_data](const uint8_t* data, size_t size) {
        if (size != AUDIO_TEST_SAMPLES) {
            printf("Received unexpected audio size: %zu bytes (expected %d)\n", size, AUDIO_TEST_SAMPLES);
            return;
        }
        
        test_user_data.audio_packets_received++;
        
        // Check if this is a reflected packet we sent
        uint8_t start_value = data[0];
        auto it = test_user_data.sent_audio_packets.find(start_value);
        
        if (it != test_user_data.sent_audio_packets.end()) {
            // Verify the packet content
            bool match = true;
            for (size_t i = 0; i < size; i++) {
                if (data[i] != it->second[i]) {
                    match = false;
                    printf("Audio data mismatch at byte %zu: received=%d, expected=%d\n",
                           i, data[i], it->second[i]);
                    break;
                }
            }
            
            if (match) {
                test_user_data.audio_packets_verified++;
                printf("Packet %d verified successfully (start value: %d)\n", 
                       test_user_data.audio_packets_verified, start_value);
            }
            
            // Remove from sent packets map
            test_user_data.sent_audio_packets.erase(it);
        } else {
            printf("Received unexpected packet with start value: %d\n", start_value);
        }
    };

    test_user_data.peer_connection = std::make_unique<rtc::PeerConnection>(config);

    // Set up connection state callback
    test_user_data.peer_connection->on_ice_connection_state_change(
        [](rtc::PeerConnectionState state) {
            printf("Connection state changed: %s\n", 
                   (state == rtc::PeerConnectionState::NEW) ? "new" :
                   (state == rtc::PeerConnectionState::CHECKING) ? "checking" :
                   (state == rtc::PeerConnectionState::CONNECTED) ? "connected" :
                   (state == rtc::PeerConnectionState::COMPLETED) ? "completed" :
                   (state == rtc::PeerConnectionState::FAILED) ? "failed" :
                   (state == rtc::PeerConnectionState::DISCONNECTED) ? "disconnected" :
                   (state == rtc::PeerConnectionState::CLOSED) ? "closed" : "unknown");
            
            if (state == rtc::PeerConnectionState::CONNECTED || 
                state == rtc::PeerConnectionState::COMPLETED) {
                connection_established = true;
            }
        });

    test_user_data.peer_connection->on_ice_candidate([&test_user_data](const std::string& sdp) {
        printf("ICE candidate generated: %s\n", sdp.c_str());
        test_user_data.ice_candidates.push_back(sdp);
    });

    // Create thread for peer connection processing
    pthread_t pc_thread;
    pthread_create(&pc_thread, nullptr, peer_connection_task, 
                   test_user_data.peer_connection.get());

    // Create offer and encode it with base64
    std::string offer = test_user_data.peer_connection->create_offer();
    printf("Local Description (Offer):\n%s\n", offer.c_str());
    
    // Encode offer with base64
    size_t encoded_len = (offer.length() * 4 / 3) + 4; // Calculate base64 output size
    char* encoded_offer = new char[encoded_len];
    base64_encode(reinterpret_cast<const unsigned char*>(offer.c_str()), 
                  offer.length(), encoded_offer, encoded_len);
    
    printf("\n=== BASE64 ENCODED OFFER ===\n%s\n=== END OF OFFER ===\n\n", 
           encoded_offer);
    
    delete[] encoded_offer;

    // Wait for user input for remote description
    printf("Please enter the BASE64 encoded remote description (answer):\n");
    std::string encoded_answer;
    std::getline(std::cin, encoded_answer);
    
    // Decode the answer
    size_t decoded_len = encoded_answer.length(); // Upper bound for decoded size
    unsigned char* decoded_answer = new unsigned char[decoded_len];
    int actual_len = base64_decode(encoded_answer.c_str(), encoded_answer.length(), 
                                   decoded_answer, decoded_len);
    
    std::string answer(reinterpret_cast<char*>(decoded_answer), actual_len);
    printf("\nDecoded Answer:\n%s\n", answer.c_str());
    
    delete[] decoded_answer;
    
    // Set remote description
    test_user_data.peer_connection->set_remote_description(answer, rtc::SdpType::ANSWER);

    // Initialize last send time
    test_user_data.last_send_time = std::chrono::steady_clock::now();
    
    int attempts = 0;
    
    while (attempts < MAX_CONNECTION_ATTEMPTS && !test_complete) {
        auto state = test_user_data.peer_connection->get_state();
        printf("Attempt %d: Connection state=%d (%s)\n", 
               attempts,
               static_cast<int>(state),
               (state == rtc::PeerConnectionState::NEW) ? "new" :
               (state == rtc::PeerConnectionState::CHECKING) ? "checking" :
               (state == rtc::PeerConnectionState::CONNECTED) ? "connected" :
               (state == rtc::PeerConnectionState::COMPLETED) ? "completed" :
               (state == rtc::PeerConnectionState::FAILED) ? "failed" :
               (state == rtc::PeerConnectionState::DISCONNECTED) ? "disconnected" :
               (state == rtc::PeerConnectionState::CLOSED) ? "closed" : "unknown");
        
        // Check if connection is established
        if (connection_established) {
            // Wait a bit for connection to stabilize
            if (attempts > 5) {
                auto now = std::chrono::steady_clock::now();
                
                // Send audio packets at 20ms intervals
                if (test_user_data.audio_packets_sent < AUDIO_SEND_COUNT) {
                    auto time_since_last = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - test_user_data.last_send_time).count();
                    
                    if (time_since_last >= AUDIO_SEND_INTERVAL_MS) {
                        // Generate random starting value N
                        uint8_t N = test_user_data.dis(test_user_data.gen);
                        
                        // Generate audio packet [N, N+160)
                        std::vector<uint8_t> audio_packet(AUDIO_TEST_SAMPLES);
                        for (int i = 0; i < AUDIO_TEST_SAMPLES; i++) {
                            audio_packet[i] = static_cast<uint8_t>((N + i) & 0xFF);
                        }
                        
                        // Store the packet for verification
                        test_user_data.sent_audio_packets[N] = audio_packet;
                        
                        // Send the packet
                        int result = test_user_data.peer_connection->send_audio(
                            audio_packet.data(), audio_packet.size());
                        
                        if (result == 0) {
                            test_user_data.audio_packets_sent++;
                            printf("Sent packet %d/%d (start value: %d)\n", 
                                   test_user_data.audio_packets_sent, AUDIO_SEND_COUNT, N);
                        } else {
                            printf("Failed to send audio packet: %d\n", result);
                        }
                        
                        test_user_data.last_send_time = now;
                    }
                } else {
                    // All packets sent, wait for reflections
                    if (test_user_data.audio_packets_verified >= AUDIO_SEND_COUNT * 0.9) {
                        // Verified at least 90% of packets
                        printf("\nAudio test completed successfully!\n");
                        printf("Sent: %d packets\n", test_user_data.audio_packets_sent);
                        printf("Received: %d packets\n", test_user_data.audio_packets_received);
                        printf("Verified: %d packets\n", test_user_data.audio_packets_verified);
                        
                        // Give the remote peer some time to process any remaining packets
                        printf("Waiting 2 seconds before closing connection...\n");
                        sleep(2);
                        test_complete = true;
                    } else if (attempts > 150) {
                        // Timeout waiting for reflections
                        printf("\nAudio test timed out.\n");
                        printf("Sent: %d packets\n", test_user_data.audio_packets_sent);
                        printf("Received: %d packets\n", test_user_data.audio_packets_received);
                        printf("Verified: %d packets\n", test_user_data.audio_packets_verified);
                        
                        // Brief wait before closing connection
                        printf("Waiting 1 second before closing connection...\n");
                        sleep(1);
                        test_complete = true;
                    }
                }
            }
        }

        attempts++;
        usleep(100000); // 100ms
        
        // Early exit if connection fails
        if (test_user_data.peer_connection->get_state() == rtc::PeerConnectionState::FAILED) {
            printf("Connection failed, breaking early\n");
            break;
        }
    }

    test_complete = true;
    
    // Properly close the peer connection
    printf("Closing peer connection...\n");
    test_user_data.peer_connection->close();
    
    // Wait for thread to exit
    pthread_join(pc_thread, nullptr);
    
    printf("Test completed with %d attempts\n", attempts);
    
    // Success if connection was established and most packets were verified
    if (connection_established && test_user_data.audio_packets_verified >= AUDIO_SEND_COUNT * 0.9) {
        printf("Test PASSED: Connection established and audio echo test successful\n");
        return 0;
    } else {
        printf("Test FAILED: Connection or audio echo test failed\n");
        return 1;
    }
}