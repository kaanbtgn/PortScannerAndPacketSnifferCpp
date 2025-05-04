# Advanced Port Scanner

A feature-rich network scanning utility for security testing and network discovery. This tool provides comprehensive port scanning capabilities with TCP/UDP scanning, OS fingerprinting, service detection, and packet sniffing functionality.

## Features

- TCP port scanning with multi-threading
- UDP port scanning
- OS fingerprinting based on TCP/IP stack behavior
- Service identification and banner grabbing
- Packet sniffing on discovered open ports
- Host discovery using ICMP and TCP-based techniques
- Extensive logging and detailed scan results

## Requirements

- Root/sudo privileges (required for raw socket operations)
- C++ compiler with C++11 support
- libpcap (for packet capture on macOS)

## Compilation Instructions

### On macOS

```bash
# Install libpcap if not already installed
brew install libpcap

# Compile the main port scanner
g++ -std=c++17 -pthread port_scanner.cpp -o port_scanner -lpcap

# Compile the host discovery tool
g++ -std=c++17 -o host_discovery host_discovery.cpp

# Compile the network scanner
g++ -std=c++17 -o netscan netscan.cpp
```

### On Linux

```bash
# Install libpcap if not already installed
sudo apt-get install libpcap-dev   # For Debian/Ubuntu
# or
sudo yum install libpcap-devel     # For CentOS/RHEL/Fedora

# Compile the main port scanner
g++ -std=c++17 -o port_scanner port_scanner.cpp -lpcap

# Compile the host discovery tool
g++ -std=c++17 -o host_discovery host_discovery.cpp

# Compile the network scanner
g++ -std=c++17 -o netscan netscan.cpp
```

## Usage

### Main Port Scanner

```bash
# Run with sudo privileges
sudo ./port_scanner [target_ip] [start_port] [end_port] [sniff_duration]

# Example: Scan localhost on all ports
sudo ./port_scanner 127.0.0.1

# Example: Scan a specific range on a remote host
sudo ./port_scanner 192.168.1.1 1 1024 10
```

The port scanner will prompt for:
- Scan mode (tcp/udp/both)
- Target IP (default: 127.0.0.1)
- Start port (default: 1)
- End port (default: 65535)
- Sniffing duration in seconds (default: 5)

### Host Discovery Tool

```bash
# Run with sudo privileges
sudo ./host_discovery <IP>

# Example
sudo ./host_discovery 192.168.1.1
```

### Network Scanner

```bash
# Run with sudo privileges
sudo ./netscan <IP> [ports]

# Example: Scan common ports 1-1024
sudo ./netscan 192.168.1.1

# Example: Scan specific port range
sudo ./netscan 192.168.1.1 1-1024

# Example: Scan specific ports
sudo ./netscan 192.168.1.1 22,80,443
```

## Files & Components

### `port_scanner.cpp`
The main port scanner implementation with comprehensive features:
- Multi-threaded TCP port scanning
- UDP port scanning
- OS fingerprinting through TCP/IP stack analysis
- Service banner grabbing
- Packet sniffing on open ports
- Detailed results logging

### `rawsock.hpp`
A RAII (Resource Acquisition Is Initialization) wrapper for raw sockets that:
- Handles socket creation and cleanup
- Simplifies raw socket operations
- Ensures proper socket closing

### `checksum.hpp`
Implements the standard Internet checksum algorithm (RFC-1071):
- Used for calculating IP and TCP header checksums
- Essential for crafting packets in raw socket operations

### `syn_scan.hpp`
A specialized SYN scan implementation:
- Uses TCP SYN packets to determine port states
- Implements cross-platform TCP/IP header handling
- Provides fast network scanning with minimal resource usage
- Multi-threaded scanning for improved performance

### `host_discovery.cpp`
Contains host discovery functionality:
- ICMP Echo (ping) based discovery
- TCP SYN ping alternative for firewalled environments
- Cross-platform implementation for Linux and macOS

### `netscan.cpp`
A simplified port scanner utility:
- Uses the SYN scanner from syn_scan.hpp
- Supports scanning port ranges or specific ports
- Presents concise output of open ports

## Log Files

The port scanner generates a log file `scan_results.log` with detailed information about:
- Scan start and end times
- Detected operating system information
- Open ports and identified services
- Banner information from services
- Scan summary with duration and port statistics

## OS Fingerprinting

The scanner uses various TCP/IP stack characteristics to identify operating systems:
- TCP Window Size
- Initial TTL
- TCP Options and their ordering
- MSS (Maximum Segment Size)
- DF (Don't Fragment) flag
- SACK capability

## Platform Compatibility

The code includes cross-platform compatibility for both Linux and macOS:
- Handles different TCP/IP header structures
- Adapts to platform-specific networking APIs
- Uses preprocessor directives to maintain a single codebase for both platforms

## Security Notice

This tool is intended for legitimate network testing and educational purposes. Always obtain proper authorization before scanning networks that you do not own or have explicit permission to test.

## License

This project is available for educational and security testing purposes.