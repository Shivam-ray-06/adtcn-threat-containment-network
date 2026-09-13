#pragma once
// http_client.hpp
// Minimal HTTP/1.1 client using raw POSIX sockets — no libcurl or any
// external dependency. This build environment can't reach external
// package mirrors for C++ libraries, and honestly, a JSON POST over
// plain HTTP doesn't need a full library: this is ~60 lines of real
// socket code, which is arguably a better demonstration of "we wrote
// this in C++" than shelling out to curl would be.

#include <string>
#include <sstream>
#include <cstring>
#include <stdexcept>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

namespace adtcn_http {

struct HttpResponse {
    int status_code = 0;
    std::string body;
};

// POSTs a JSON body to http://host:port/path and returns the response.
// Throws std::runtime_error on any socket-level failure.
inline HttpResponse post_json(const std::string& host, int port,
                               const std::string& path, const std::string& json_body) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        throw std::runtime_error("DNS/address resolution failed for " + host);
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        throw std::runtime_error("socket() failed");
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock);
        freeaddrinfo(res);
        throw std::runtime_error("connect() failed to " + host + ":" + port_str);
    }
    freeaddrinfo(res);

    std::ostringstream request;
    request << "POST " << path << " HTTP/1.1\r\n"
            << "Host: " << host << ":" << port << "\r\n"
            << "Content-Type: application/json\r\n"
            << "Content-Length: " << json_body.size() << "\r\n"
            << "Connection: close\r\n"
            << "\r\n"
            << json_body;

    std::string req_str = request.str();
    ssize_t sent_total = 0;
    while (sent_total < (ssize_t)req_str.size()) {
        ssize_t n = send(sock, req_str.c_str() + sent_total, req_str.size() - sent_total, 0);
        if (n <= 0) { close(sock); throw std::runtime_error("send() failed"); }
        sent_total += n;
    }
    // Signal we're done writing so the server (even if it ignores our
    // "Connection: close" header) doesn't sit waiting for a follow-up
    // request on the same socket — avoids a mutual-wait hang.
    shutdown(sock, SHUT_WR);

    // Safety net: never block on recv() forever even if something else
    // goes wrong server-side.
    struct timeval tv{};
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    std::string raw_response;
    char buf[4096];
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) {
        raw_response.append(buf, n);
    }
    close(sock);

    HttpResponse response;
    size_t status_start = raw_response.find(' ');
    if (status_start != std::string::npos) {
        response.status_code = std::atoi(raw_response.c_str() + status_start + 1);
    }
    size_t body_start = raw_response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        response.body = raw_response.substr(body_start + 4);
    }
    return response;
}

// GETs a path and returns the response.
inline HttpResponse get(const std::string& host, int port, const std::string& path) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        throw std::runtime_error("DNS/address resolution failed for " + host);
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); throw std::runtime_error("socket() failed"); }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock);
        freeaddrinfo(res);
        throw std::runtime_error("connect() failed");
    }
    freeaddrinfo(res);

    std::ostringstream request;
    request << "GET " << path << " HTTP/1.1\r\n"
            << "Host: " << host << ":" << port << "\r\n"
            << "Connection: close\r\n\r\n";
    std::string req_str = request.str();
    send(sock, req_str.c_str(), req_str.size(), 0);
    shutdown(sock, SHUT_WR);

    struct timeval tv{};
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    std::string raw_response;
    char buf[4096];
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) raw_response.append(buf, n);
    close(sock);

    HttpResponse response;
    size_t status_start = raw_response.find(' ');
    if (status_start != std::string::npos) {
        response.status_code = std::atoi(raw_response.c_str() + status_start + 1);
    }
    size_t body_start = raw_response.find("\r\n\r\n");
    if (body_start != std::string::npos) response.body = raw_response.substr(body_start + 4);
    return response;
}

} // namespace adtcn_http
