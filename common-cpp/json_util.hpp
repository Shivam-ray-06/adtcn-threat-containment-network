#pragma once
// json_util.hpp
// Minimal JSON helpers for the C++ agents. We only ever need to BUILD
// a handful of known event shapes and READ a handful of known
// response fields (threat_score, response_level, evidence_hash) for
// console output — so this deliberately isn't a general JSON parser,
// just enough string handling to do that safely.

#include <string>
#include <vector>
#include <utility>
#include <cctype>

namespace adtcn_json {

inline std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c;
        }
    }
    return out;
}

// Builds the JSON body for a POST /events call.
// metadata_pairs: list of (key, value) string pairs -> becomes a flat
// JSON object of strings (sufficient for this project's metadata use).
inline std::string build_event(const std::string& entity_id,
                                const std::string& event_type,
                                const std::string& source,
                                const std::vector<std::pair<std::string, std::string>>& metadata_pairs = {},
                                const std::string& graph_src = "",
                                const std::string& graph_dst = "",
                                const std::string& graph_label = "") {
    std::string j = "{";
    j += "\"entity_id\":\"" + escape(entity_id) + "\",";
    j += "\"event_type\":\"" + escape(event_type) + "\",";
    j += "\"source\":\"" + escape(source) + "\",";

    j += "\"metadata\":{";
    for (size_t i = 0; i < metadata_pairs.size(); i++) {
        if (i > 0) j += ",";
        j += "\"" + escape(metadata_pairs[i].first) + "\":\"" + escape(metadata_pairs[i].second) + "\"";
    }
    j += "}";

    if (!graph_src.empty()) j += ",\"graph_src\":\"" + escape(graph_src) + "\"";
    if (!graph_dst.empty()) j += ",\"graph_dst\":\"" + escape(graph_dst) + "\"";
    if (!graph_label.empty()) j += ",\"graph_label\":\"" + escape(graph_label) + "\"";

    j += "}";
    return j;
}

// Finds "key":<number> in a flat-ish JSON string and returns the number,
// or -1 if not found. Good enough for pulling threat_score etc. out of
// our own backend's response for console display.
inline long extract_int(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\":";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return -1;
    pos += needle.length();
    size_t end = pos;
    bool neg = false;
    if (end < json.size() && json[end] == '-') { neg = true; end++; }
    size_t digits_start = end;
    while (end < json.size() && std::isdigit((unsigned char)json[end])) end++;
    if (end == digits_start) return -1;
    long val = std::stol(json.substr(digits_start, end - digits_start));
    return neg ? -val : val;
}

// Finds "key":"value" in a JSON string and returns value, or "" if not found.
inline std::string extract_string(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\":\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return "";
    pos += needle.length();
    size_t end = json.find("\"", pos);
    if (end == std::string::npos) return "";
    return json.substr(pos, end - pos);
}

} // namespace adtcn_json
