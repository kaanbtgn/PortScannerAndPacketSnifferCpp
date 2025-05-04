/*
 * Host discovery (ICMP Echo    + TCP SYN‑ping)
 * Çalışma: macOS 13+, Ubuntu/Kali, Debian, Fedora…  (root yetkisi şart)
 */
#include <iostream>
#include <cstring>
#include <chrono>

/* ---- platform ortak başlıklar ---- */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>

#ifdef __APPLE__
/* ---------- Linux‑style ICMP header ported to macOS ---------- */
struct icmphdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};
#define ICMP_ECHO      8
#define ICMP_ECHOREPLY 0
#endif

/* ===== ICMP field helpers (cross‑platform) ===== */
#ifdef __APPLE__
  #define ICMP_SET_ID(h,v)   ((h)->id = (v))
  #define ICMP_SET_SEQ(h,v)  ((h)->sequence = (v))
  #define ICMP_GET_ID(h)     ((h)->id)
#else
  #define ICMP_SET_ID(h,v)   ((h)->un.echo.id = (v))
  #define ICMP_SET_SEQ(h,v)  ((h)->un.echo.sequence = (v))
  #define ICMP_GET_ID(h)     ((h)->un.echo.id)
#endif

/* ===== TCP checksum field helper ===== */
#ifdef __APPLE__
  #define TCP_CHECK_FIELD(h)  ((h)->th_sum)
#else
  #define TCP_CHECK_FIELD(h)  ((h)->check)
#endif
#include <unistd.h>

#ifdef __APPLE__
  #include <netinet/ip.h>          // BSD struct ip
  using iphdr  = struct ip;        // alias so code stays portable

  /* TCP field/flag helpers so Linux & macOS build from same source */
  #define SET_TCP_SRC(h,v)    ((h)->th_sport = (v))
  #define SET_TCP_DST(h,v)    ((h)->th_dport = (v))
  #define SET_TCP_SEQ(h,v)    ((h)->th_seq  = (v))
  #define SET_TCP_DOFF(h,v)   ((h)->th_off = (v))
  #define SET_TCP_WINDOW(h,v) ((h)->th_win  = (v))
  #define SET_TCP_SYN_FLAG(h) ((h)->th_flags = TH_SYN)
  #define IS_SYN_ACK(h)       (((h)->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
#else   /* Linux/other */
  #define SET_TCP_SRC(h,v)    ((h)->source = (v))
  #define SET_TCP_DST(h,v)    ((h)->dest   = (v))
  #define SET_TCP_SEQ(h,v)    ((h)->seq    = (v))
  #define SET_TCP_DOFF(h,v)   ((h)->doff   = (v))
  #define SET_TCP_WINDOW(h,v) ((h)->window = (v))
  #define SET_TCP_SYN_FLAG(h) ((h)->syn = 1)
  #define IS_SYN_ACK(h)       ((h)->syn && (h)->ack)
#endif

/* ---- ip header tanımı: macOS'ta iphdr yok ---- */
#include <netinet/ip.h>          // BSD‑tarzı struct ip

/* ---- proje başlıklarımız ---- */
#include "checksum.hpp"
#include "rawsock.hpp"

/* ========== ICMP ECHO ========== */
bool icmp_echo(const std::string& ip, int timeout_ms = 1000)
{
    RawSocket sock(IPPROTO_ICMP);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &dst.sin_addr);

    /* sadece ICMP başlık + küçük payload → IP başlığını kernel oluşturacak */
    std::uint8_t pkt[sizeof(icmphdr) + 16]{};              // 16 B dolgu
    auto* icmp = reinterpret_cast<icmphdr*>(pkt);
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    ICMP_SET_ID(icmp, htons(0x5678));
    ICMP_SET_SEQ(icmp, htons(1));
    std::memset(pkt + sizeof(icmphdr), 0xAA, 16);
    icmp->checksum = checksum(pkt, sizeof(pkt));

    sendto(sock.fd(), pkt, sizeof(pkt), 0,
           reinterpret_cast<sockaddr*>(&dst), sizeof(dst));

    fd_set rfds; FD_ZERO(&rfds); FD_SET(sock.fd(), &rfds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};

    if (select(sock.fd() + 1, &rfds, nullptr, nullptr, &tv) > 0) {
        std::uint8_t buf[1024];
        ssize_t n = recv(sock.fd(), buf, sizeof(buf), 0);
        if (n > 0) {
            auto* rip   = reinterpret_cast<iphdr*>(buf);
            auto* ricmp = reinterpret_cast<icmphdr*>(buf + rip->ip_hl * 4);
            if (ricmp->type == ICMP_ECHOREPLY && ICMP_GET_ID(ricmp) == htons(0x5678))
                return true;
        }
    }
    return false;
}

/* ========== TCP SYN “ping” ========== */
bool tcp_syn_ping(const std::string& ip, uint16_t dport = 443, int timeout_ms = 1000)
{
    RawSocket sock(IPPROTO_TCP);
    int optval = 1;
    setsockopt(sock.fd(), IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &dst.sin_addr);

    std::uint8_t packet[40]{};                       // IP(20) + TCP(20)
    auto* iph = reinterpret_cast<iphdr*>(packet);
    auto* tcp = reinterpret_cast<tcphdr*>(packet + sizeof(iphdr));

    /* IP */
    iph->ip_hl   = 5;
    iph->ip_v    = 4;
    iph->ip_len  = htons(sizeof(packet));
    iph->ip_ttl  = 64;
    iph->ip_p    = IPPROTO_TCP;
    iph->ip_src.s_addr = 0;                           // kernel doldurur
    iph->ip_dst   = dst.sin_addr;

    /* TCP */
    SET_TCP_SRC(tcp, htons(40000 + (rand() % 10000)));
    SET_TCP_DST(tcp, htons(dport));
    SET_TCP_SEQ(tcp, htonl(0xABCDEF01));
    SET_TCP_DOFF(tcp, 5);
    SET_TCP_SYN_FLAG(tcp);
    SET_TCP_WINDOW(tcp, htons(64240));

    /* TCP checksum (pseudo‑header) */
    struct pseudo {
        uint32_t src, dst;
        uint8_t  zero, proto;
        uint16_t len;
    } ph{};
    ph.src   = iph->ip_src.s_addr;
    ph.dst   = iph->ip_dst.s_addr;
    ph.zero  = 0;
    ph.proto = IPPROTO_TCP;
    ph.len   = htons(sizeof(tcphdr));

    std::uint8_t cbuf[sizeof(ph) + sizeof(tcphdr)];
    std::memcpy(cbuf, &ph, sizeof(ph));
    std::memcpy(cbuf + sizeof(ph), tcp, sizeof(tcphdr));
    TCP_CHECK_FIELD(tcp) = checksum(cbuf, sizeof(cbuf));

    /* IP checksum */
    iph->ip_sum = checksum(iph, sizeof(iphdr));

    sendto(sock.fd(), packet, sizeof(packet), 0,
           reinterpret_cast<sockaddr*>(&dst), sizeof(dst));

    fd_set rfds; FD_ZERO(&rfds); FD_SET(sock.fd(), &rfds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};

    if (select(sock.fd() + 1, &rfds, nullptr, nullptr, &tv) > 0) {
        std::uint8_t buf[1024];
        ssize_t n = recv(sock.fd(), buf, sizeof(buf), 0);
        if (n > 0) {
            auto* rip  = reinterpret_cast<iphdr*>(buf);
            auto* rtcp = reinterpret_cast<tcphdr*>(buf + rip->ip_hl * 4);
            if (IS_SYN_ACK(rtcp))                 // SYN‑ACK = host alive
                return true;
        }
    }
    return false;
}

/* ========== main ========== */
int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "kullanım: " << argv[0] << " <IP>\n";
        return 1;
    }
    std::string ip = argv[1];

    auto t0 = std::chrono::steady_clock::now();
    bool up = icmp_echo(ip);
    if (!up) up = tcp_syn_ping(ip);
    auto ms = std::chrono::duration<double, std::milli>(
                  std::chrono::steady_clock::now() - t0).count();

    std::cout << "[*] " << ip << "  →  "
              << (up ? "YAŞIYOR" : "YANIT YOK")
              << "   (" << ms << " ms)\n";
    return up ? 0 : 2;
}