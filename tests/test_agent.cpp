#include <iostream>
#include <string>
#include <cstring>
#include "agent.hpp"

void test_gather_host(rtc::IceAgent& agent) {
    agent.gather_candidate("", "", "");
}

void test_gather_turn(rtc::IceAgent& agent, const std::string& turnserver, 
                      const std::string& username, const std::string& credential) {
    agent.gather_candidate(turnserver, username, credential);
}

void test_gather_stun(rtc::IceAgent& agent, const std::string& stunserver) {
    agent.gather_candidate(stunserver, "", "");
}

int main(int argc, char* argv[]) {
    rtc::IceAgent agent;

    std::string stunserver = "stun:stun.l.google.com:19302";
    std::string turnserver = "";
    std::string username = "";
    std::string credential = "";
    std::string description;

    agent.create();

    test_gather_host(agent);
    test_gather_stun(agent, stunserver);
    test_gather_turn(agent, turnserver, username, credential);
    agent.get_local_description(description);

    std::cout << "sdp:\n" << description << std::endl;

    agent.destroy();

    return 0;
}