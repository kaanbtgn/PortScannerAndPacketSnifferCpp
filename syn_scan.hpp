#pragma once
#include <vector>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <queue>
#include <condition_variable>
#include <arpa/inet.h>
#include "rawsock.hpp"
#include "checksum.hpp"

/* -------- Platform‑bağımlı TCP alan yardımcıları -------- */
#ifdef __APPLE__
  #include <netinet/ip.h>
  #include <netinet/tcp.h>
  using iphdr = struct ip;
  #define TCP_SRC(h)    ((h)->th_sport)
  #define TCP_DST(h)    ((h)->th_dport)
  #define TCP_SEQ(h)    ((h)->th_seq)
  #define TCP_FLAGS(h)  ((h)->th_flags)
  #define TCP_WIN(h)    ((h)->th_win)
  #define IS_SYN_ACK(h) (((h)->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
  #define IS_RST(h)     ((h)->th_flags & TH_RST)
  #define TCP_SET_CHECK(h,v) ((h)->th_sum = (v))
  #define SET_TCP_DOFF(h,v)   ((h)->th_off = (v))
  #define SET_TCP_SYN_FLAG(h) ((h)->th_flags = TH_SYN)
#else   /* Linux */
  #include <linux/ip.h>
  #include <netinet/tcp.h>
  #define TCP_SRC(h)    ((h)->source)
  #define TCP_DST(h)    ((h)->dest)
  #define TCP_SEQ(h)    ((h)->seq)
  #define TCP_FLAGS(h)  (*(uint8_t*)((h))+13)
  #define TCP_WIN(h)    ((h)->window)
  #define IS_SYN_ACK(h) ((h)->syn && (h)->ack)
  #define IS_RST(h)     ((h)->rst)
  #define TCP_SET_CHECK(h,v) ((h)->check = (v))
  #define SET_TCP_DOFF(h,v)   ((h)->doff = (v))
  #define SET_TCP_SYN_FLAG(h) ((h)->syn = 1)
#endif

enum class PortState : uint8_t { OPEN, CLOSED, FILTERED };

struct ScanResult {
    uint16_t port;
    PortState state;
};

class SynScanner {
    std::string target_ip_;
    sockaddr_in dst_;
    int thread_cnt_;
    int timeout_ms_;
    std::vector<uint16_t> ports_;
    std::unordered_map<uint16_t,PortState> result_;
    std::mutex mtx_;
    std::atomic<bool> stop_{false};

    /* ----- listener ----- */
    void listener()
    {
        RawSocket rsock(IPPROTO_TCP);
        int one = 1; setsockopt(rsock.fd(), IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

        while (!stop_) {
            uint8_t buf[4096];
            ssize_t n = recv(rsock.fd(), buf, sizeof(buf), 0);
            if (n <= 0) continue;

            auto* ip  = reinterpret_cast<iphdr*>(buf);
            auto* tcp = reinterpret_cast<tcphdr*>(buf + (ip->ip_hl * 4));

            uint16_t dport = ntohs(TCP_DST(tcp));   // bizim kaynak portumuz
            uint16_t sport = ntohs(TCP_SRC(tcp));   // taranan hedef port

            /* SYN‑ACK ⇒ open,   RST ⇒ closed */
            PortState st;
            if (IS_SYN_ACK(tcp))
                st = PortState::OPEN;
            else if (IS_RST(tcp))
                st = PortState::CLOSED;
            else
                continue;

            std::lock_guard<std::mutex> lg(mtx_);
            auto it = result_.find(sport);
            if (it != result_.end() && it->second == PortState::FILTERED)
                it->second = st;
        }
    }

    /* ----- worker: tek port gönderir ----- */
    void send_syn(uint16_t port, RawSocket& rsock)
    {
        uint8_t packet[40]{};
        auto* ip  = reinterpret_cast<iphdr*>(packet);
        auto* tcp = reinterpret_cast<tcphdr*>(packet + sizeof(iphdr));

        /* IP */
        ip->ip_hl  = 5;
        ip->ip_v   = 4;
        ip->ip_len = htons(sizeof(packet));
        ip->ip_ttl = 64;
        ip->ip_p   = IPPROTO_TCP;
        ip->ip_src.s_addr = 0;
        ip->ip_dst = dst_.sin_addr;
        ip->ip_sum = checksum(ip, sizeof(iphdr));

        /* TCP */
        TCP_SRC(tcp) = htons(60000);   // sabit kaynak port
        TCP_DST(tcp) = htons(port);
        TCP_SEQ(tcp) = htonl(0xBEEF + port);
        SET_TCP_DOFF(tcp, 5);
        SET_TCP_SYN_FLAG(tcp);
        TCP_WIN(tcp) = htons(64240);

        struct pseudo {
            uint32_t src, dst; uint8_t zero, proto; uint16_t len;
        } ph{ip->ip_src.s_addr, ip->ip_dst.s_addr, 0, IPPROTO_TCP, htons(sizeof(tcphdr))};

        uint8_t cbuf[sizeof(ph)+sizeof(tcphdr)];
        std::memcpy(cbuf,&ph,sizeof(ph));
        std::memcpy(cbuf+sizeof(ph),tcp,sizeof(tcphdr));
        TCP_SET_CHECK(tcp, checksum(cbuf,sizeof(cbuf)));

        sendto(rsock.fd(), packet, sizeof(packet), 0,
               reinterpret_cast<sockaddr*>(&dst_), sizeof(dst_));
    }

public:
    SynScanner(const std::string& ip,
               std::vector<uint16_t> ports,
               int timeout_ms = 3000)
        : target_ip_(ip),
          thread_cnt_(std::thread::hardware_concurrency()),
          timeout_ms_(timeout_ms),
          ports_(std::move(ports))
    {
        dst_.sin_family = AF_INET;
        inet_pton(AF_INET, target_ip_.c_str(), &dst_.sin_addr);
        for (auto p: ports_) result_[p] = PortState::FILTERED;
    }

    std::vector<ScanResult> run()
    {
        /* listener */
        std::thread t_listener(&SynScanner::listener, this);

        /* worker pool */
        RawSocket rsock(IPPROTO_TCP);
        int one = 1; setsockopt(rsock.fd(), IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

        std::atomic<size_t> idx{0};
        auto worker = [&]{
            size_t i;
            while ((i = idx.fetch_add(1)) < ports_.size())
                send_syn(ports_[i], rsock);
        };
        std::vector<std::thread> workers;
        for (int i=0;i<thread_cnt_;++i) workers.emplace_back(worker);

        /* timeout bekle */
        for (auto& th: workers) th.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout_ms_));
        stop_ = true;
        t_listener.join();

        std::vector<ScanResult> out;
        for (auto& kv: result_)
            out.push_back({kv.first, kv.second});

        return out;
    }
};