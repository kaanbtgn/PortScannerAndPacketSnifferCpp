#pragma once
#include <stdexcept>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

/* Basit RAII ham‑socket sarmalayıcısı */
class RawSocket {
    int fd_;
public:
    explicit RawSocket(int proto)
    {
        fd_ = ::socket(AF_INET, SOCK_RAW, proto);
        if (fd_ < 0)
            throw std::runtime_error("raw socket açılırken hata (root / sudo gerekiyor)");
    }
    ~RawSocket() { if (fd_ >= 0) ::close(fd_); }

    int  fd() const               { return fd_; }
    RawSocket(const RawSocket&)            = delete;
    RawSocket& operator=(const RawSocket&) = delete;
};