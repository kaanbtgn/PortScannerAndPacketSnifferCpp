#pragma once
#include <cstdint>
#include <cstddef>

/* RFC‑1071 standart internet checksum */
inline uint16_t checksum(const void* data, std::size_t len)
{
    auto* buf = reinterpret_cast<const uint16_t*>(data);
    uint32_t sum = 0;

    while (len > 1) { sum += *buf++; len -= 2; }
    if (len) sum += *reinterpret_cast<const uint8_t*>(buf);

    /* carry‑over */
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

    return static_cast<uint16_t>(~sum);
}
