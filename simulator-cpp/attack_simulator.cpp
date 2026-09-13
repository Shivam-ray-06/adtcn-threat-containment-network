// attack_simulator.cpp
// Plays out the scripted PC-47 attack scenario end-to-end (C++
// version). Same scenario as the original design doc and the earlier
// Python prototype, reimplemented here for the all-C++/Java/JS stack.
//
// Build:
//   g++ -O2 -std=c++17 -I../common-cpp attack_simulator.cpp -o attack_simulator
// Run:
//   ./attack_simulator PC-47 ../decoys/finance_admin_credentials.txt flow_log.jsonl

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include "http_client.hpp"
#include "json_util.hpp"

static const std::string BACKEND_HOST = "localhost";
static const int BACKEND_PORT = 8000;

double now_seconds()
{
    return std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
}

void sleep_s(double seconds)
{
    std::this_thread::sleep_for(std::chrono::milliseconds((long)(seconds * 1000)));
}

std::string send_event(const std::string &entity_id, const std::string &event_type,
                       const std::vector<std::pair<std::string, std::string>> &metadata = {},
                       const std::string &graph_src = "", const std::string &graph_dst = "",
                       const std::string &graph_label = "")
{
    std::string body = adtcn_json::build_event(entity_id, event_type, "attack_simulator",
                                               metadata, graph_src, graph_dst, graph_label);
    auto resp = adtcn_http::post_json(BACKEND_HOST, BACKEND_PORT, "/events", body);
    long score = adtcn_json::extract_int(resp.body, "threat_score");
    std::string level = adtcn_json::extract_string(resp.body, "response_level");
    std::cout << "[attacker] " << event_type << "  score=" << score
              << "  level=" << level << std::endl;
    return resp.body;
}

void append_flow_record(const std::string &log_path, const std::string &src, const std::string &dst)
{
    std::ofstream f(log_path, std::ios::app);
    f << "{\"src\":\"" << src << "\",\"dst\":\"" << dst << "\",\"timestamp\":" << now_seconds() << "}\n";
}

int main(int argc, char *argv[])
{
    std::string host = argc > 1 ? argv[1] : "PC-47";
    std::string decoy_path = argc > 2 ? argv[2] : "../decoys/finance_admin_credentials.txt";
    std::string flow_log_path = argc > 3 ? argv[3] : "flow_log.jsonl";

    std::cout << "\n=== ADTCN Attack Simulation (C++) :: attacker lands on " << host << " ===\n"
              << std::endl;

    {
        std::ofstream touch(flow_log_path, std::ios::app);
    } // ensure file exists

    std::vector<std::string> environment_hosts;
    for (int i = 1; i <= 8; i++)
    {
        char buf[16];
        snprintf(buf, sizeof(buf), "PC-%02d", i);
        environment_hosts.push_back(buf);
    }

    std::cout << "[step 1] initial compromise: unusual process created" << std::endl;
    send_event(host, "unusual_process", {{"cmdline", "powershell -enc <base64>"}});
    sleep_s(1.5);

    std::cout << "\n[step 2] execution hardening: attempting privilege escalation" << std::endl;
    send_event(host, "privilege_escalation", {{"method", "token impersonation attempt"}});
    sleep_s(1.0);

    std::cout << "\n[step 3] reconnaissance: scanning internal network" << std::endl;
    for (const auto &dest : environment_hosts)
    {
        append_flow_record(flow_log_path, host, dest);
        sleep_s(0.3);
    }
    sleep_s(2.5); // give network_sensor time to pick up the burst

    std::cout << "\n[step 4] credential hunting: opening " << decoy_path << std::endl;
    {
        std::ifstream decoy_file(decoy_path);
        std::string discard((std::istreambuf_iterator<char>(decoy_file)), std::istreambuf_iterator<char>());
        // This real read is what endpoint_agent's inotify watch detects independently.
    }
    sleep_s(1.5);

    std::cout << "\n[step 5] credential usage: authenticating with stolen (decoy) credential" << std::endl;
    send_event(host, "decoy_credential_used", {{"username", "finance_admin"}},
               "Finance Share / Decoy Credential File", "DATABASE-01",
               "authenticated with decoy credential");
    sleep_s(1.5);

    std::cout << "\n[step 6] lateral movement: PC -> SERVER-03 -> DATABASE-01" << std::endl;
    append_flow_record(flow_log_path, host, "SERVER-03");
    send_event(host, "lateral_movement", {{"path", host + "->SERVER-03->DATABASE-01"}},
               host, "SERVER-03", "lateral movement");
    sleep_s(1.0);
    append_flow_record(flow_log_path, "SERVER-03", "DATABASE-01");
    send_event("SERVER-03", "lateral_movement", {{"path", host + "->SERVER-03->DATABASE-01"}},
               "SERVER-03", "DATABASE-01", "lateral movement");

    std::cout << "\n[step 7] impact: ransomware begins encrypting user files" << std::endl;
    send_event(host, "ransomware_activity", {{"files_affected", "rapid encryption burst"}},
               host, "Finance Share", "ransomware impact");

    std::cout << "\n=== Scenario complete. Check the dashboard for the final threat score, ===" << std::endl;
    std::cout << "=== the autonomous response taken, and the reconstructed attack graph.  ===\n"
              << std::endl;
    return 0;
}
