#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sys/socket.h>
#ifdef __linux__
#include <linux/if_packet.h>
#include <net/ethernet.h>
#endif
#include <netdb.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <iomanip>
#include "rawsock.hpp"
#include "checksum.hpp"
#include <queue>
#include <algorithm>
#include <condition_variable>
#include <set>
#include <ifaddrs.h>
#include <net/if.h>
#include <pcap.h>

// Platform uyumluluğu için iphdr alias'ı (macOS)
#ifdef __APPLE__
using iphdr = struct ip;
#endif

// Common service ports and their names
const std::map<uint16_t, std::string> COMMON_SERVICES = {
    {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"},
    {53, "DNS"}, {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"},
    {443, "HTTPS"}, {445, "SMB"}, {3306, "MySQL"}, {3389, "RDP"},
    {5432, "PostgreSQL"}, {27017, "MongoDB"}
};

// OS Fingerprinting constants and structures
struct OSFingerprint {
    uint16_t window_size;
    uint8_t ttl;
    bool df_flag;
    uint16_t mss;
    uint8_t window_scaling;
    bool sack_permitted;
    bool timestamp_supported;
    std::vector<uint8_t> options;
};

struct OSSignature {
    std::string os_name;
    uint16_t window_size_min;
    uint16_t window_size_max;
    uint8_t ttl_min;
    uint8_t ttl_max;
    bool df_flag;
    uint16_t mss;
    bool sack_required;
};

const std::vector<OSSignature> OS_SIGNATURES = {
    {"Windows 10/11", 64240, 65535, 64, 128, true, 1460, true},
    {"Linux (Modern)", 29200, 29200, 64, 64, true, 1460, true},
    {"macOS", 65535, 65535, 64, 64, true, 1460, true},
    {"FreeBSD", 65535, 65535, 64, 64, true, 1460, true},
    {"OpenBSD", 16384, 16384, 64, 64, true, 1460, true},
    {"Embedded Linux", 5840, 5840, 64, 64, true, 1460, false},
};

// TCP Options for fingerprinting
const uint8_t TCP_OPTIONS[] = {
    0x02, 0x04, 0x05, 0xb4,  // MSS
    0x01,                     // NOP
    0x03, 0x03, 0x08,        // Window Scale
    0x01,                     // NOP
    0x04, 0x02,              // SACK Permitted
    0x08, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Timestamp
};

struct ScanResult {
    bool is_open;
    std::string service;
    std::string banner;
    OSFingerprint os_fingerprint;
};

// TTL-based OS guess helper
std::string guess_os_by_ttl(uint8_t ttl) {
    if (ttl >= 100) return "Windows/Embedded";
    if (ttl >= 90)  return "FreeBSD/OpenBSD";
    if (ttl >= 60)  return "Linux/macOS";
    if (ttl > 0)    return "Linux/macOS (many hops)";
    return "Unknown OS";
}
// Needed for popen/pclose fallback ping
#include <cstdio>
#include <cstdlib>

// Resolve a hostname to IPv4 string; returns original input if resolution fails
std::string resolve_hostname(const std::string& host) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;        // IPv4 only
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
        return host;                  // return unchanged on failure
    }
    char ipstr[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET,
              &reinterpret_cast<struct sockaddr_in*>(res->ai_addr)->sin_addr,
              ipstr, sizeof(ipstr));
    freeaddrinfo(res);
    return std::string(ipstr);
}

enum class PortState { OPEN, CLOSED, FILTERED };

class PortScanner {
public:
    // Capture packets on all open TCP ports
    void sniff_open_ports(int duration_sec = 5);
private:
    std::string target_ip;
    std::map<uint16_t, ScanResult> results;
    std::mutex results_mutex;
    std::atomic<int> ports_scanned{0};
    std::ofstream log_file;
    int total_ports;
    OSFingerprint target_os;
    bool os_detected{false};

    void fingerprint_os(uint16_t open_port);
    void sniff_port(uint16_t port, int duration_sec = 5);
    void send_probe(uint16_t port, const std::string& data = "HELLO\r\n");
    void send_raw_payload(uint16_t port, const std::vector<uint8_t>& data);

    std::string detect_os(const OSFingerprint& fp) {
        std::vector<std::pair<std::string, int>> scores;
        
        for (const auto& sig : OS_SIGNATURES) {
            int score = 0;
            
            // Window size check
            if (fp.window_size >= sig.window_size_min && 
                fp.window_size <= sig.window_size_max) {
                score += 30;
            }
            
            // TTL check
            if (fp.ttl >= sig.ttl_min && fp.ttl <= sig.ttl_max) {
                score += 20;
            }
            
            // DF flag check
            if (fp.df_flag == sig.df_flag) {
                score += 10;
            }
            
            // MSS check
            if (fp.mss == sig.mss) {
                score += 20;
            }
            
            // SACK check
            if (fp.sack_permitted == sig.sack_required) {
                score += 10;
            }
            
            scores.push_back({sig.os_name, score});
        }
        
        // Find the best match
        auto best_match = std::max_element(scores.begin(), scores.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });
            
        if (best_match->second >= 60) {  // Require at least 60% match
            return best_match->first;
        }
        
        return "Unknown OS";
    }

    uint16_t send_syn_packet(uint16_t port) {
        RawSocket sock(IPPROTO_TCP);
        int optval = 1;
        setsockopt(sock.fd(), IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        inet_pton(AF_INET, target_ip.c_str(), &dst.sin_addr);

        std::uint8_t packet[sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(TCP_OPTIONS)]{};
        struct ip* iph = reinterpret_cast<struct ip*>(packet);
        struct tcphdr* tcp = reinterpret_cast<struct tcphdr*>(packet + sizeof(struct ip));

        // IP header
        iph->ip_hl = 5;
        iph->ip_v = 4;
        iph->ip_len = htons(sizeof(packet));
        iph->ip_ttl = 64;
        iph->ip_p = IPPROTO_TCP;
        // Pick a source address: if we are probing localhost, use 127.0.0.1
        // otherwise use the first non‑loopback address of the host.
        char local_ip[INET_ADDRSTRLEN] = "127.0.0.1";
        if (target_ip != "127.0.0.1") {
            struct ifaddrs* ifa = nullptr;
            getifaddrs(&ifa);
            for (auto p = ifa; p; p = p->ifa_next) {
                if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET &&
                    !(p->ifa_flags & IFF_LOOPBACK)) {
                    inet_ntop(AF_INET, &((struct sockaddr_in*)p->ifa_addr)->sin_addr,
                              local_ip, sizeof(local_ip));
                    break;
                }
            }
            freeifaddrs(ifa);
        }
        inet_pton(AF_INET, local_ip, &iph->ip_src);
        iph->ip_dst = dst.sin_addr;

        // choose a random ephemeral source port for SYN
        uint16_t src_port = 40000 + (rand() % 10000);
        // TCP header with options
        tcp->th_sport = htons(src_port);
        tcp->th_dport = htons(port);
        tcp->th_seq = htonl(0xABCDEF01);
        tcp->th_off = 5 + sizeof(TCP_OPTIONS)/4;
        tcp->th_flags = TH_SYN;
        tcp->th_win = htons(64240);

        std::memcpy(packet + sizeof(struct ip) + sizeof(struct tcphdr),
                   TCP_OPTIONS, sizeof(TCP_OPTIONS));

        struct pseudo {
            uint32_t src, dst;
            uint8_t zero, proto;
            uint16_t len;
        } ph{};
        ph.src = iph->ip_src.s_addr;
        ph.dst = iph->ip_dst.s_addr;
        ph.zero = 0;
        ph.proto = IPPROTO_TCP;
        ph.len = htons(sizeof(struct tcphdr) + sizeof(TCP_OPTIONS));

        std::uint8_t cbuf[sizeof(ph) + sizeof(struct tcphdr) + sizeof(TCP_OPTIONS)];
        std::memcpy(cbuf, &ph, sizeof(ph));
        std::memcpy(cbuf + sizeof(ph), tcp, sizeof(struct tcphdr));
        std::memcpy(cbuf + sizeof(ph) + sizeof(struct tcphdr),
                   TCP_OPTIONS, sizeof(TCP_OPTIONS));
        tcp->th_sum = checksum(cbuf, sizeof(cbuf));

        iph->ip_sum = checksum(iph, sizeof(struct ip));
        if (sendto(sock.fd(), packet, sizeof(packet), 0,
                   reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) > 0) {
            return src_port;
        }
        return 0;
    }

    bool analyze_syn_ack(const uint8_t* packet, size_t size, OSFingerprint& fp) {
        if (size < sizeof(struct ip) + sizeof(struct tcphdr)) {
            return false;
        }

        const struct ip* ip = reinterpret_cast<const struct ip*>(packet);
        const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(packet + ip->ip_hl * 4);

        // Extract fingerprint data
        fp.window_size = ntohs(tcp->th_win);
        fp.ttl = ip->ip_ttl;
        fp.df_flag = (ntohs(ip->ip_off) & IP_DF) != 0;

        // Analyze TCP options
        const uint8_t* options = reinterpret_cast<const uint8_t*>(tcp + 1);
        int opt_len = (tcp->th_off * 4) - sizeof(struct tcphdr);
        
        fp.options.assign(options, options + opt_len);
        
        // Parse options
        for (int i = 0; i < opt_len;) {
            switch (options[i]) {
                case 0: // End of options
                    i = opt_len;
                    break;
                case 1: // NOP
                    i++;
                    break;
                case 2: // MSS
                    if (i + 4 <= opt_len) {
                        fp.mss = ntohs(*reinterpret_cast<const uint16_t*>(options + i + 2));
                    }
                    i += 4;
                    break;
                case 3: // Window Scale
                    if (i + 3 <= opt_len) {
                        fp.window_scaling = options[i + 2];
                    }
                    i += 3;
                    break;
                case 4: // SACK permitted
                    fp.sack_permitted = true;
                    i += 2;
                    break;
                case 8: // Timestamp
                    fp.timestamp_supported = true;
                    i += 10;
                    break;
                default:
                    if (i + 1 < opt_len) {
                        i += options[i + 1];
                    } else {
                        i = opt_len;
                    }
            }
        }

        return true;
    }

    PortState check_port_response(uint16_t port, int timeout_ms = 1000) {
        // First try regular TCP connect
        int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (tcp_sock < 0) {
            std::cerr << "Failed to create TCP socket: " << strerror(errno) << std::endl;
            return PortState::FILTERED;
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr) <= 0) {
            std::cerr << "Invalid IP address: " << target_ip << std::endl;
            close(tcp_sock);
            return PortState::FILTERED;
        }

        // Set non-blocking
        int flags = fcntl(tcp_sock, F_GETFL, 0);
        fcntl(tcp_sock, F_SETFL, flags | O_NONBLOCK);

        int res = connect(tcp_sock, (struct sockaddr*)&addr, sizeof(addr));
        if (res < 0) {
            if (errno == EINPROGRESS) {
                fd_set wfds;
                struct timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
                
                FD_ZERO(&wfds);
                FD_SET(tcp_sock, &wfds);
                
                res = select(tcp_sock + 1, nullptr, &wfds, nullptr, &tv);
                if (res > 0) {
                    int error = 0;
                    socklen_t len = sizeof(error);
                    if (getsockopt(tcp_sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
                        close(tcp_sock);
                        return PortState::FILTERED;
                    }
                    close(tcp_sock);
                    if (error == 0) return PortState::OPEN;
                    if (error == ECONNREFUSED) return PortState::CLOSED;
                    return PortState::FILTERED;
                } else if (res == 0) {
                    // Timeout => filtered
                    close(tcp_sock);
                    return PortState::FILTERED;
                }
            }
            close(tcp_sock);
            return PortState::FILTERED;
        }

        close(tcp_sock);
        return PortState::OPEN;
    }

    std::string get_service_banner(uint16_t port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return "";

        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);

        connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        timeval tv{2, 0};

        if (select(sock + 1, nullptr, &wfds, nullptr, &tv) <= 0) {
            close(sock);
            return "";
        }

        fcntl(sock, F_SETFL, flags);

        char buf[1024] = {};
        timeval recv_tv{2, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_tv, sizeof(recv_tv));
        
        ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
        close(sock);

        if (n > 0) {
            buf[n] = '\0';
            return std::string(buf);
        }
        
        /* ---------- 2. HTTP GET denemesi ---------- */
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            int blk = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, blk & ~O_NONBLOCK);          /* blocking */
            if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
                const char* req = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
                send(sock, req, strlen(req), 0);
                char buf2[2048] = {};
                ssize_t n2 = recv(sock, buf2, sizeof(buf2) - 1, 0);
                if (n2 > 0) { buf2[n2] = '\0'; close(sock); return std::string(buf2); }
            }
            close(sock);
        }
        return "";
    }

    std::string identify_service(uint16_t port, const std::string& banner) {
        auto it = COMMON_SERVICES.find(port);
        if (it != COMMON_SERVICES.end()) {
            return it->second;
        }
        
        if (!banner.empty()) {
            if (banner.find("SSH") != std::string::npos) return "SSH";
            if (banner.find("HTTP") != std::string::npos) return "HTTP";
            if (banner.find("FTP") != std::string::npos) return "FTP";
            if (banner.find("SMTP") != std::string::npos) return "SMTP";
            if (banner.find("MySQL") != std::string::npos) return "MySQL";
        }
        
        return "Unknown";
    }

    void scan_port(uint16_t port) {
        PortState state = check_port_response(port);
        bool is_open = (state == PortState::OPEN);
        bool is_closed = (state == PortState::CLOSED);
        bool is_filtered = (state == PortState::FILTERED);
        if (is_closed) {
            // Closed: RST received
            std::lock_guard<std::mutex> lock(results_mutex);
            results[port] = {false, "closed", "", {}};
            ports_scanned++;
            return;
        }
        if (is_filtered) {
            // Filtered: no response
            std::lock_guard<std::mutex> lock(results_mutex);
            results[port] = {false, "filtered", "", {}};
            ports_scanned++;
            return;
        }
        if (is_open && !os_detected) {
            fingerprint_os(port);   // first attempt
        } else if (is_open && os_detected == false) {
            fingerprint_os(port);   // keep trying until detected
        }
        std::string banner = is_open ? get_service_banner(port) : "";
        std::string service = is_open ? identify_service(port, banner) : "";
        // If no banner yet, send a small probe and re‑attempt
        if (banner.empty() && is_open) {
            send_probe(port);                       // default "HELLO\r\n"
            banner = get_service_banner(port);
            service = identify_service(port, banner);
        }
        // FTP and SMTP specific probes
        if (is_open && service == "Unknown") {
            if (port == 21) {
                send_probe(port, "SYST\r\n");
                banner = get_service_banner(port);
                service = identify_service(port, banner);
            } else if (port == 25) {
                send_probe(port, "EHLO example.com\r\n");
                banner = get_service_banner(port);
                service = identify_service(port, banner);
            }
        }
        // Better banner / service probe
        if (service == "Unknown" && is_open) {
            if (banner.find("HTTP") != std::string::npos ||
                banner.find("GET /") != std::string::npos) service = "HTTP";
            else if (banner.rfind("220", 0) == 0 && banner.find("SMTP") != std::string::npos) service = "SMTP";
            else if (banner.find("SSH-") != std::string::npos) service = "SSH";
        }
        // Additional protocol probes for common services
        if (is_open) {
            if ((port == 80 || port == 443) && service == "Unknown") {
                send_probe(port, "HEAD / HTTP/1.0\r\nHost: " + target_ip + "\r\n\r\n");
                banner = get_service_banner(port);
                service = identify_service(port, banner);
            }
            if (port == 22 && service == "Unknown") {
                banner = get_service_banner(port);
                service = identify_service(port, banner);
            }
            if (port == 21 && service == "Unknown") {
                send_probe(port, "SYST\r\n");
                banner = get_service_banner(port);
                service = identify_service(port, banner);
            }
            if (port == 25 && service == "Unknown") {
                send_probe(port, "EHLO example.com\r\n");
                banner = get_service_banner(port);
                service = identify_service(port, banner);
            }
            if (port == 3306 && service == "Unknown") {
                std::vector<uint8_t> mysql_ping = {0x0a};
                send_raw_payload(port, mysql_ping);
                banner = get_service_banner(port);
                service = identify_service(port, banner);
            }
            if (port == 6379 && service == "Unknown") {
                send_probe(port, "*1\r\n$4\r\nPING\r\n");
                banner = get_service_banner(port);
                service = identify_service(port, banner);
            }
            if (port == 5432 && service == "Unknown") {
                std::vector<uint8_t> psql_ssl = {0x00,0x00,0x00,0x08,0x04,0xd2,0x16,0x2f};
                send_raw_payload(port, psql_ssl);
                banner = get_service_banner(port);
                service = identify_service(port, banner);
            }
        }
        {
            std::lock_guard<std::mutex> lock(results_mutex);
            results[port] = {is_open, service, banner, target_os};
        }
        ports_scanned++;
    }

    // UDP banner grabbing helpers
    std::string get_udp_banner(uint16_t port) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return "";
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);
        // DNS probe
        if (port == 53) {
            unsigned char dns_query[] = {0x12,0x34,1,0,0,1,0,0,0,0,0,0,3,'w','w','w',6,'g','o','o','g','l','e',3,'c','o','m',0,0,1,0,1};
            sendto(sock, dns_query, sizeof(dns_query), 0, (struct sockaddr*)&addr, sizeof(addr));
        } else if (port == 123) { // NTP
            unsigned char ntp_query[48] = {0x1B};
            sendto(sock, ntp_query, sizeof(ntp_query), 0, (struct sockaddr*)&addr, sizeof(addr));
        } else if (port == 161) { // SNMP
            unsigned char snmp_query[] = {0x30,0x26,0x02,0x01,0x00,0x04,0x06,'p','u','b','l','i','c',0xA0,0x19,0x02,0x04,0x70,0x69,0x6E,0x67,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0B,0x30,0x09,0x06,0x05,0x2B,0x06,0x01,0x02,0x01,0x05,0x00};
            sendto(sock, snmp_query, sizeof(snmp_query), 0, (struct sockaddr*)&addr, sizeof(addr));
        } else {
            char dummy[1] = {0};
            sendto(sock, dummy, 1, 0, (struct sockaddr*)&addr, sizeof(addr));
        }
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        struct timeval tv{1,0};
        if (select(sock+1, &rfds, nullptr, nullptr, &tv) > 0) {
            char buf[512] = {};
            socklen_t alen = sizeof(addr);
            ssize_t n = recvfrom(sock, buf, sizeof(buf)-1, 0, (struct sockaddr*)&addr, &alen);
            close(sock);
            if (n > 0) return std::string(buf, n);
        }
        close(sock);
        return "";
    }

    void scan_udp_port(uint16_t port, std::map<uint16_t, ScanResult>& udp_results, std::mutex& udp_mutex) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return;
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);
        char dummy[1] = {0};
        sendto(sock, dummy, 1, 0, (struct sockaddr*)&addr, sizeof(addr));
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        struct timeval tv{1,0};
        bool is_open = false;
        if (select(sock+1, &rfds, nullptr, nullptr, &tv) > 0) {
            char buf[512] = {};
            socklen_t alen = sizeof(addr);
            ssize_t n = recvfrom(sock, buf, sizeof(buf)-1, 0, (struct sockaddr*)&addr, &alen);
            if (n > 0) is_open = true;
        } else {
            // No response: UDP port is open|filtered (per UDP scanning logic)
            is_open = true;
        }
        std::string banner = is_open ? get_udp_banner(port) : "";
        std::string service = is_open ? identify_service(port, banner) : "";
        {
            std::lock_guard<std::mutex> lock(udp_mutex);
            udp_results[port] = {is_open, service, banner, {}};
        }
        close(sock);
    }

public:

    PortScanner(const std::string& ip) : target_ip(ip) {
        log_file.open("scan_results.log", std::ios::app);
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        log_file << "\n=== Scan started at " << std::ctime(&now_c);
    }

    ~PortScanner() {
        if (log_file.is_open()) {
            auto now = std::chrono::system_clock::now();
            auto now_c = std::chrono::system_clock::to_time_t(now);
            log_file << "=== Scan completed at " << std::ctime(&now_c);
            log_file.close();
        }
    }

    void scan_ports(uint16_t start_port = 1, uint16_t end_port = 65535, int max_threads = 100) {
        total_ports = end_port - start_port + 1;
        ports_scanned = 0;

        std::cout << "[*] Starting port scan for " << target_ip << "\n";
        log_file << "[*] Starting port scan for " << target_ip << "\n";
        auto scan_start = std::chrono::steady_clock::now();

        std::queue<uint16_t> port_queue;
        for (uint32_t p = start_port; p <= end_port; ++p)  // use 32‑bit loop var to avoid wrap‑around at 65535
            port_queue.push(static_cast<uint16_t>(p));

        std::mutex queue_mutex;
        std::vector<std::thread> workers;

        auto worker = [&]() {
            while (true) {
                uint16_t port;
                {
                    std::lock_guard<std::mutex> lock(queue_mutex);
                    if (port_queue.empty()) return;
                    port = port_queue.front();
                    port_queue.pop();
                }
                scan_port(port); // ports_scanned burada artırılıyor
            }
        };

        for (int i = 0; i < max_threads; ++i)
            workers.emplace_back(worker);

        // Progress bar
        while (true) {
            float progress = (float)ports_scanned / total_ports * 100;
            std::cout << "\rProgress: " << std::fixed << std::setprecision(2)
                      << progress << "% (" << ports_scanned << "/" << total_ports << " ports)" << std::flush;
            if (ports_scanned >= total_ports) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        for (auto& t : workers) t.join();
        std::cout << "\rProgress: 100.00% (" << total_ports << "/" << total_ports << " ports)\n";

        auto scan_end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(scan_end - scan_start);

        std::cout << "\n\n=== Scan Results ===\n";
        log_file << "\n=== Scan Results ===\n";

        if (os_detected) {
            std::string detected_os = detect_os(target_os);
            std::cout << "Detected Operating System: " << detected_os << "\n";
            log_file << "Detected Operating System: " << detected_os << "\n";
            
            std::cout << "OS Fingerprint Details:\n";
            std::cout << "- Window Size: " << target_os.window_size << "\n";
            std::cout << "- TTL: " << (int)target_os.ttl << "\n";
            std::cout << "- DF Flag: " << (target_os.df_flag ? "Yes" : "No") << "\n";
            std::cout << "- MSS: " << target_os.mss << "\n";
            std::cout << "- SACK: " << (target_os.sack_permitted ? "Yes" : "No") << "\n";
            std::cout << "- Timestamp: " << (target_os.timestamp_supported ? "Yes" : "No") << "\n\n";
            
            log_file << "OS Fingerprint Details:\n";
            log_file << "- Window Size: " << target_os.window_size << "\n";
            log_file << "- TTL: " << (int)target_os.ttl << "\n";
            log_file << "- DF Flag: " << (target_os.df_flag ? "Yes" : "No") << "\n";
            log_file << "- MSS: " << target_os.mss << "\n";
            log_file << "- SACK: " << (target_os.sack_permitted ? "Yes" : "No") << "\n";
            log_file << "- Timestamp: " << (target_os.timestamp_supported ? "Yes" : "No") << "\n\n";
        }
        else if (target_os.ttl != 0) {
            std::string ttl_guess = guess_os_by_ttl(target_os.ttl);
            std::cout << "TTL‑based OS guess: " << ttl_guess
                      << " (TTL=" << static_cast<int>(target_os.ttl) << ")\n\n";
            log_file << "TTL‑based OS guess: " << ttl_guess
                     << " (TTL=" << static_cast<int>(target_os.ttl) << ")\n\n";
        }

        int open_ports = 0;
        for (const auto& [port, result] : results) {
            if (result.is_open) {
                open_ports++;
                std::cout << "[+] Port " << port << " is open";
                log_file << "[+] Port " << port << " is open";
                
                if (!result.service.empty()) {
                    std::cout << " - Service: " << result.service;
                    log_file << " - Service: " << result.service;
                }
                
                if (!result.banner.empty()) {
                    std::cout << " - Banner: " << result.banner;
                    log_file << " - Banner: " << result.banner;
                }
                std::cout << "\n";
                log_file << "\n";
            }
        }

        std::cout << "\n=== Scan Summary ===\n";
        std::cout << "Total ports scanned: " << total_ports << "\n";
        std::cout << "Open ports found: " << open_ports << "\n";
        std::cout << "Scan duration: " << duration.count() << " seconds\n";

        log_file << "\n=== Scan Summary ===\n";
        log_file << "Total ports scanned: " << total_ports << "\n";
        log_file << "Open ports found: " << open_ports << "\n";
        log_file << "Scan duration: " << duration.count() << " seconds\n";

        // if (open_ports > 0) sniff_open_ports(5);  // capture 5 s per open port
    }

    void scan_udp_ports(uint16_t start_port, uint16_t end_port, int max_threads, std::map<uint16_t, ScanResult>& udp_results) {
        std::mutex udp_mutex;
        std::queue<uint16_t> port_queue;
        for (uint32_t p = start_port; p <= end_port; ++p)  // use 32‑bit loop var to avoid wrap‑around at 65535
            port_queue.push(static_cast<uint16_t>(p));
        std::vector<std::thread> workers;
        auto worker = [&]() {
            while (true) {
                uint16_t port;
                {
                    std::lock_guard<std::mutex> lock(udp_mutex);
                    if (port_queue.empty()) return;
                    port = port_queue.front();
                    port_queue.pop();
                }
                scan_udp_port(port, udp_results, udp_mutex);
            }
        };
        for (int i = 0; i < max_threads; ++i)
            workers.emplace_back(worker);
        for (auto& t : workers) t.join();
    }
};


int main(int argc, char* argv[]) {
    std::string target_ip;
    uint16_t start_port = 1, end_port = 65535;
    std::string mode = "both";
    int sniff_duration = 5;   // varsayılan
    std::cout << "Tarama modu seçin (tcp/udp/both) [both]: ";
    std::getline(std::cin, mode);
    if (mode.empty()) mode = "both";
    if (argc < 2) {
        std::cout << "Hedef IP adresini girin [127.0.0.1]: ";
        std::cin >> target_ip;
        if (target_ip.empty()) target_ip = "127.0.0.1";
        std::cout << "Başlangıç portu [1]: ";
        std::string s; std::getline(std::cin >> std::ws, s);
        if (!s.empty()) start_port = std::stoi(s);
        std::cout << "Bitiş portu [65535]: ";
        std::getline(std::cin, s);
        if (!s.empty()) end_port = std::stoi(s);
        std::cout << "Dinleme süresi saniye cinsinden [5]: ";
        std::getline(std::cin, s);
        if (!s.empty()) sniff_duration = std::stoi(s);
    } else {
        target_ip = argv[1];
        if (argc > 2) start_port = std::stoi(argv[2]);
        if (argc > 3) end_port = std::stoi(argv[3]);
        if (argc > 4) sniff_duration = std::stoi(argv[4]);
    }
    // Resolve hostname to IP if needed
    target_ip = resolve_hostname(target_ip);
    PortScanner scanner(target_ip);
    if (mode == "tcp" || mode == "both") {
        scanner.scan_ports(start_port, end_port, 100);
    }
    if (mode == "udp" || mode == "both") {
        std::map<uint16_t, ScanResult> udp_results;
        scanner.scan_udp_ports(start_port, end_port, 100, udp_results);
        std::cout << "\n=== UDP Scan Results ===\n";
        int open_udp = 0;
        for (const auto& [port, result] : udp_results) {
            if (result.is_open) {
                open_udp++;
                std::cout << "[+] UDP Port " << port << " is open";
                if (!result.service.empty()) std::cout << " - Service: " << result.service;
                if (!result.banner.empty()) std::cout << " - Banner: " << result.banner;
                std::cout << "\n";
            }
        }
        std::cout << "\nUDP open ports found: " << open_udp << "\n";
    }
    // TCP taraması bittikten sonra açık portlarda paket yakala
    if (mode == "tcp" || mode == "both")
        scanner.sniff_open_ports(sniff_duration);

    return 0;
} 
// OS fingerprinting helper: called once per scan when first open TCP port is found
void PortScanner::fingerprint_os(uint16_t open_port) {
    if (os_detected) return;           // already done

    // Send a crafted SYN with options to the open port, get src_port
    uint16_t src_port = send_syn_packet(open_port);
    if (!src_port) return;

#ifdef __linux__
    int recv_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
#else
    RawSocket sock(IPPROTO_TCP);
    int recv_sock = sock.fd();
    int optval = 1;
    setsockopt(recv_sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));
#endif

    uint8_t buf[65535];
    sockaddr_in src{};
    socklen_t slen = sizeof(src);
    fd_set rfds; FD_ZERO(&rfds); FD_SET(recv_sock, &rfds);
    timeval tv{1, 0};
    if (select(recv_sock + 1, &rfds, nullptr, nullptr, &tv) > 0) {
        ssize_t n = recvfrom(recv_sock, buf, sizeof(buf), 0,
                             reinterpret_cast<sockaddr*>(&src), &slen);
        if (n > 0) {
            // parse headers
            const struct ip* iphdr = reinterpret_cast<const struct ip*>(buf);
            int iplen = iphdr->ip_hl * 4;
            if (iphdr->ip_p != IPPROTO_TCP || n < iplen + sizeof(tcphdr)) {
                // Not TCP or too short
                goto after_fingerprint_recv;
            }
            const struct tcphdr* tcph = reinterpret_cast<const struct tcphdr*>(buf + iplen);
            // match ports and flags
            if (ntohs(tcph->th_sport) != open_port ||
                ntohs(tcph->th_dport) != src_port ||
                (tcph->th_flags & (TH_SYN|TH_ACK)) != (TH_SYN|TH_ACK)) {
                goto after_fingerprint_recv;
            }
            OSFingerprint fp{};
            if (analyze_syn_ack(buf, n, fp)) {
                target_os = fp;
                os_detected = true;
            }
        }
    }
after_fingerprint_recv:
#ifdef __linux__
    if (recv_sock >= 0) close(recv_sock);
#endif
    // If still not detected, try ICMP echo to read TTL
    if (!os_detected) {
        int icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (icmp >= 0) {
            uint8_t pkt[64] = {};
            pkt[0] = 8; // Echo request
            pkt[1] = 0; // Code
            pkt[2] = pkt[3] = 0;
            *((uint16_t*)(pkt + 6)) = htons(0x1234); // id
            *((uint16_t*)(pkt + 8)) = htons(1);      // seq
            *((uint16_t*)(pkt + 2)) = checksum(pkt, 8);
            sockaddr_in dst{}; dst.sin_family = AF_INET;
            inet_pton(AF_INET, target_ip.c_str(), &dst.sin_addr);
            sendto(icmp, pkt, 8, 0, (sockaddr*)&dst, sizeof(dst));

            fd_set rf; FD_ZERO(&rf); FD_SET(icmp, &rf);
            timeval tv2{1,0};
            if (select(icmp+1, &rf, nullptr, nullptr, &tv2) > 0) {
                uint8_t buf2[128]; recv(icmp, buf2, sizeof(buf2), 0);
                auto ip2 = reinterpret_cast<struct ip*>(buf2);
                uint8_t ttl = ip2->ip_ttl;
                target_os.ttl = ttl;
                os_detected = true;
                std::string g = guess_os_by_ttl(ttl);
                std::cout << "[!] TTL‑based guess: " << g << " (TTL=" << (int)ttl << ")\n";
                log_file << "[!] TTL‑based guess: " << g << " (TTL=" << (int)ttl << ")\n";
            }
            close(icmp);
        }
    }
    // If still not detected, try system ping and parse TTL
    if (!os_detected) {
        std::string cmd = "ping -c1 -W1 " + target_ip;
        FILE* f = popen(cmd.c_str(), "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                char* p = strstr(line, "ttl=");
                if (p) {
                    int ttl = atoi(p + 4);
                    if (ttl > 0) {
                        target_os.ttl = ttl;
                        os_detected = true;
                        std::string g = guess_os_by_ttl(ttl);
                        std::cout << "[!] Ping TTL-based guess: " << g << " (TTL=" << ttl << ")\n";
                        log_file << "[!] Ping TTL-based guess: " << g << " (TTL=" << ttl << ")\n";
                    }
                    break;
                }
            }
            pclose(f);
        }
    }
}
// --- Packet Sniffer --------------------------------------------------------
// Sniffing artık main()'den kullanıcı tanımlı süreyle çağrılacak

void PortScanner::sniff_port(uint16_t port, int duration_sec) {
    std::cout << "\n--- Sniffing traffic on port " << port
              << " for " << duration_sec << " seconds ---\n";
    log_file << "\n--- Sniffing traffic on port " << port
             << " for " << duration_sec << " seconds ---\n";
#ifdef __APPLE__
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
        std::cerr << "pcap_findalldevs failed: " << errbuf << "\n";
        return;
    }
    char* dev = alldevs->name;   // first device

    pcap_t* handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (!handle) { std::cerr << "pcap_open_live failed: " << errbuf << "\n"; pcap_freealldevs(alldevs); return; }

    // Compile BPF filter for the port and host
    std::string filter_expr = "tcp port " + std::to_string(port) +
                              " or udp port " + std::to_string(port) +
                              " or host " + target_ip;
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_expr.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "pcap filter error: " << pcap_geterr(handle) << "\n";
        pcap_close(handle); pcap_freealldevs(alldevs); return;
    }

    auto end_time = std::chrono::steady_clock::now() + std::chrono::seconds(duration_sec);
    while (std::chrono::steady_clock::now() < end_time) {
        struct pcap_pkthdr* header;
        const u_char* data;
        int res = pcap_next_ex(handle, &header, &data);
        if (res == 1) {
            const struct ip* iph = reinterpret_cast<const struct ip*>(data + 14); // skip Ethernet
            int iphdr_len = iph->ip_hl * 4;
            if (iph->ip_p == IPPROTO_TCP) {
                const struct tcphdr* t = reinterpret_cast<const struct tcphdr*>(data + 14 + iphdr_len);
                std::cout << "TCP " << ntohs(t->th_sport) << " → " << ntohs(t->th_dport) << "\n";
                log_file << "TCP " << ntohs(t->th_sport) << " → " << ntohs(t->th_dport) << "\n";
            } else if (iph->ip_p == IPPROTO_UDP) {
                const struct udphdr* u = reinterpret_cast<const struct udphdr*>(data + 14 + iphdr_len);
                std::cout << "UDP " << ntohs(u->uh_sport) << " → " << ntohs(u->uh_dport) << "\n";
                log_file << "UDP " << ntohs(u->uh_sport) << " → " << ntohs(u->uh_dport) << "\n";
            }
        }
    }
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    std::cout << "--- Finished sniffing port " << port << " ---\n";
    log_file << "--- Finished sniffing port " << port << " ---\n";
    return;
#endif
#ifndef __APPLE__
    #ifdef __linux__
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    #else
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    #endif
    if (sock < 0) {
        perror("raw socket");
        return;
    }

    // Set read timeout equal to duration
    timeval tv{duration_sec, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t buf[65535];
    while (true) {
        ssize_t len = recv(sock, buf, sizeof(buf), 0);
        if (len <= 0) break;

        const struct ip* iph = reinterpret_cast<struct ip*>(buf);
        int ip_hdr_len = iph->ip_hl * 4;

        if (iph->ip_p == IPPROTO_TCP && len >= ip_hdr_len + sizeof(tcphdr)) {
            const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(buf + ip_hdr_len);
            uint16_t sport = ntohs(tcp->th_sport);
            uint16_t dport = ntohs(tcp->th_dport);
            if (sport == port || dport == port) {
                std::cout << "TCP "
                          << sport << " → " << dport
                          << "  |  Seq=" << ntohl(tcp->th_seq)
                          << "  Ack=" << ntohl(tcp->th_ack)
                          << "\n";
                log_file << "TCP "
                         << sport << " → " << dport
                         << "  |  Seq=" << ntohl(tcp->th_seq)
                         << "  Ack=" << ntohl(tcp->th_ack)
                         << "\n";
            }
        } else if (iph->ip_p == IPPROTO_UDP && len >= ip_hdr_len + sizeof(udphdr)) {
            const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(buf + ip_hdr_len);
            uint16_t sport = ntohs(udp->uh_sport);
            uint16_t dport = ntohs(udp->uh_dport);
            if (sport == port || dport == port) {
                std::cout << "UDP "
                          << sport << " → " << dport
                          << "  |  Len=" << ntohs(udp->uh_ulen)
                          << "\n";
                log_file << "UDP "
                         << sport << " → " << dport
                         << "  |  Len=" << ntohs(udp->uh_ulen)
                         << "\n";
            }
        }
    }
    close(sock);
    std::cout << "--- Finished sniffing port " << port << " ---\n";
    log_file << "--- Finished sniffing port " << port << " ---\n";
#endif
}

// Simple TCP probe: connect and send arbitrary data
void PortScanner::send_probe(uint16_t port, const std::string& data) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return;
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    inet_pton(AF_INET, target_ip.c_str(), &a.sin_addr);
    if (connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0) {
        send(s, data.c_str(), data.size(), 0);
    }
    close(s);
}

// Sniff every open TCP port discovered in results map
void PortScanner::sniff_open_ports(int duration_sec) {
    for (const auto& [port, res] : results) {
        if (res.is_open) {
            sniff_port(port, duration_sec);
        }
    }
}
// ---------------------------------------------------------------------------
// [INFO] For best packet sniffing results:
//   - On Linux, use a raw socket or AF_PACKET to capture all packets.
//   - On macOS, use libpcap (pcap_open_live) to capture packets (since raw sockets can't sniff).
//   - You may need root privileges for raw sockets or pcap.
//   - Consider using tcpdump/wireshark/pcap APIs for advanced sniffing.
void PortScanner::send_raw_payload(uint16_t port, const std::vector<uint8_t>& data) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return;
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    inet_pton(AF_INET, target_ip.c_str(), &a.sin_addr);
    if (connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0) {
        send(s, data.data(), data.size(), 0);
    }
    close(s);
}