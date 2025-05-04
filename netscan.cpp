#include <iostream>
#include <vector>
#include <algorithm>
#include "syn_scan.hpp"
// #include "host_discovery.hpp"   // host_is_up() fonksiyonu ayırırsak

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "kullanım: " << argv[0] << " <IP> [ports]\n";
        std::cerr << "ports = 1-1024  veya  22,80,443\n";
        return 1;
    }
    std::string target = argv[1];

    /* --- port listesi --- */
    std::vector<uint16_t> ports;
    if (argc >=3) {
        std::string s = argv[2];
        if (s.find('-') != std::string::npos) {
            int a,b; sscanf(s.c_str(), "%d-%d",&a,&b);
            for (int p=a; p<=b; ++p) ports.push_back(p);
        } else {
            size_t pos=0;
            for (auto& tok : {s}) ;
        }
    } else {
        for (int p=1;p<=1024;++p) ports.push_back(p);
    }

    /* --- host discovery (opsiyonel) --- */
    // if (!host_is_up(target)) {
    //     std::cout << "Hedef yanıt vermiyor.\n";
    //     return 2;
    // }

    SynScanner scanner(target, ports);
    auto res = scanner.run();

    /* --- rapor --- */
    std::sort(res.begin(), res.end(),
              [](auto& a,auto& b){return a.port<b.port;});

    std::cout << "\nPORT  STATE\n";
    for (auto& r: res) {
        const char* st = (r.state==PortState::OPEN? "OPEN":
                         (r.state==PortState::CLOSED? "CLOSED":"FILTERED"));
        if (r.state == PortState::OPEN)
            std::cout << r.port << "   " << st << '\n';
    }
}