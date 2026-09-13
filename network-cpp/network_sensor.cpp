// network_sensor.cpp
// Network behavior monitor (C++). Tails a JSONL flow-record log (like
// `tail -f`) and applies real detection logic: internal scanning
// (one source touching many distinct destinations quickly) and
// abnormal first-contact with sensitive hosts.
//
// Build:
//   g++ -O2 -std=c++17 -I../common-cpp network_sensor.cpp -o network_sensor
// Run:
//   ./network_sensor ../simulator/flow_log.jsonl

#include <iostream>
#include <fstream>
#include <string>
#include <deque>
#include <set>
#include <map>
#include <thread>
#include <chrono>
#include "http_client.hpp"
#include "json_util.hpp"

static const std::string BACKEND_HOST = "localhost";
static const int BACKEND_PORT = 8000;
static const double SCAN_WINDOW_SECONDS = 10.0;
static const size_t SCAN_DISTINCT_DEST_THRESHOLD = 5;
static const std::set<std::string> SENSITIVE_DESTINATIONS = {"DATABASE-01", "SERVER-03"};

struct FlowRecord {
    std::string src, dst;
    double timestamp;
};

// Extremely small parser for our own flat flow-log line shape:
// {"src": "PC-47", "dst": "PC-01", "timestamp": 1234567890.123}
bool parse_flow_line(const std::string& line, FlowRecord& out) {
    out.src = adtcn_json::extract_string(line, "src");
    out.dst = adtcn_json::extract_string(line, "dst");
    if (out.src.empty() || out.dst.empty()) return false;

    std::string needle = "\"timestamp\":";
    size_t pos = line.find(needle);
    if (pos == std::string::npos) {
        out.timestamp = std::chrono::duration<double>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    } else {
        pos += needle.length();
        out.timestamp = std::stod(line.substr(pos));
    }
    return true;
}

void send_event(const std::string& entity_id, const std::string& event_type,
                 const std::vector<std::pair<std::string, std::string>>& metadata,
                 const std::string& graph_src = "", const std::string& graph_dst = "",
                 const std::string& graph_label = "") {
    std::string body = adtcn_json::build_event(entity_id, event_type, "network_sensor",
                                                 metadata, graph_src, graph_dst, graph_label);
    try {
        auto resp = adtcn_http::post_json(BACKEND_HOST, BACKEND_PORT, "/events", body);
        long score = adtcn_json::extract_int(resp.body, "threat_score");
        std::cout << "[net] sent " << event_type << " for " << entity_id
                  << " -> score=" << score << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[net] failed to send event: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <flow_log_path>" << std::endl;
        return 1;
    }
    std::string log_path = argv[1];

    std::ifstream file(log_path);
    if (!file.is_open()) {
        std::cerr << "[net] could not open " << log_path << std::endl;
        return 1;
    }
    file.seekg(0, std::ios::end); // jump to end, react only to new lines during the demo

    std::cout << "[net] tailing " << log_path << " for flow records..." << std::endl;

    std::deque<FlowRecord> recent;                 // sliding window of recent connections
    std::set<std::pair<std::string, std::string>> known_pairs;

    std::string line;
    while (true) {
        file.clear(); // clear EOF flag so we can keep reading as the file grows
        if (std::getline(file, line)) {
            if (line.empty()) continue;
            FlowRecord rec;
            if (!parse_flow_line(line, rec)) continue;

            recent.push_back(rec);
            while (!recent.empty() && rec.timestamp - recent.front().timestamp > SCAN_WINDOW_SECONDS) {
                recent.pop_front();
            }

            std::set<std::string> distinct_dests_recent;
            for (const auto& r : recent) {
                if (r.src == rec.src) distinct_dests_recent.insert(r.dst);
            }

            if (distinct_dests_recent.size() >= SCAN_DISTINCT_DEST_THRESHOLD) {
                std::cout << "[net] SCANNING DETECTED: " << rec.src << " touched "
                          << distinct_dests_recent.size() << " hosts in "
                          << SCAN_WINDOW_SECONDS << "s" << std::endl;
                send_event(rec.src, "internal_scanning",
                           {{"distinct_destinations", std::to_string(distinct_dests_recent.size())}},
                           rec.src, "Internal Network (scan)",
                           "scanned " + std::to_string(distinct_dests_recent.size()) + " hosts");
            }

            auto pair_key = std::make_pair(rec.src, rec.dst);
            if (SENSITIVE_DESTINATIONS.count(rec.dst) && !known_pairs.count(pair_key)) {
                std::cout << "[net] ABNORMAL COMMUNICATION: " << rec.src << " -> " << rec.dst
                          << " (first contact)" << std::endl;
                send_event(rec.src, "suspicious_external_connection",
                           {{"dst", rec.dst}, {"reason", "first-time contact with sensitive host"}},
                           rec.src, rec.dst, "first contact");
            }
            known_pairs.insert(pair_key);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        }
    }
    return 0;
}
