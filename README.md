# network_task4
# README: Ping and Traceroute Tools

## Overview
This repository contains implementations of two essential network diagnostic tools:
1. **Ping**: Used to test connectivity and measure round-trip time (RTT) between the source and a target IP address.
2. **Traceroute**: Used to determine the path packets take to reach a destination and measure the latency at each hop.

Both tools are implemented in C using raw sockets, providing low-level control over ICMP (Internet Control Message Protocol) packets.

---

## Features

### Ping
- Sends ICMP echo requests to a target IP (IPv4 or IPv6).
- Measures round-trip time (RTT).
- Reports statistics such as packet loss, minimum/average/maximum RTT.
- Supports adjustable packet count and flood mode.

### Traceroute
- Identifies intermediate hops to the target IP.
- Sends ICMP echo requests with varying TTL (Time To Live) values.
- Reports RTT for each hop.
- Handles timeouts and retries.

---

## File Structure

- **ping.c**: Implementation of the Ping tool.
- **traceroute.c**: Implementation of the Traceroute tool.
- **Makefile**: Build system to compile both programs.

---

## Compilation

### Prerequisites
- Make sure your computer supports ipv6, if it doesn't
the program wont run properly.
- GCC compiler
- Linux operating system (required for raw socket support)
- Root permissions (necessary for raw socket operations)

### Steps
1. Open a terminal and navigate to the project directory.
2. Run the following command to build both programs:
   ```bash
   make
   ```
3. This will generate the executables:
   - `ping`
   - `traceroute`

---

## Usage

### Ping
Run the Ping tool with the following syntax:
```bash
sudo ./ping -a <target_address> -t <ip_version> [-c <count>] [-f]
```

#### Arguments:
- `-a <target_address>`: Target IP address.
- `-t <ip_version>`: IP version (4 for IPv4, 6 for IPv6).
- `-c <count>`: Number of ICMP echo requests to send (default: 4).
- `-f`: Enable flood mode (sends packets as fast as possible).

#### Example:
```bash
sudo ./ping -a 8.8.8.8 -t 4 -c 10
```

### Traceroute
Run the Traceroute tool with the following syntax:
```bash
sudo ./traceroute -a <target_address>
```

#### Arguments:
- `-a <target_address>`: Target IP address.

#### Example:
```bash
sudo ./traceroute -a 8.8.8.8
```

---

## Features in Detail

### Ping
- Calculates ICMP packet checksums to ensure data integrity.
- Uses `flood mode` for stress testing network connectivity.
- Displays packet loss and RTT statistics upon completion.

### Traceroute
- Dynamically adjusts TTL values to discover intermediate hops.
- Handles ICMP Time Exceeded and Echo Reply responses.
- Implements a retry mechanism for unreachable nodes.

---

## Limitations
- Requires root permissions to create raw sockets.
- Designed for Linux systems; compatibility with other platforms is not guaranteed.
- Assumes the network allows ICMP traffic, which may be blocked by firewalls.

---

## Example Outputs

### Ping:
```
PING 8.8.8.8 with 64 bytes of data:
64 bytes from 8.8.8.8: icmp_seq=0 ttl=115 time=16.60 ms
64 bytes from 8.8.8.8: icmp_seq=1 ttl=115 time=14.91 ms

--- 8.8.8.8 ping statistics ---
4 packets transmitted, 4 received, 0.0% packet loss
rtt min/avg/max = 13.06/14.48/16.60 ms
```

### Traceroute:
```
traceroute to 8.8.8.8, 30 hops max
 1  192.168.1.1 (192.168.1.1)  1.20 ms  1.15 ms  1.18 ms
 2  10.0.0.1 (10.0.0.1)  5.34 ms  5.28 ms  5.30 ms
 3  8.8.8.8 (8.8.8.8)  16.60 ms  14.91 ms  13.06 ms
```

---

## Cleaning Up
To remove all compiled files and executables, run:
```bash
make clean
```

---

## Authors
Salome Timsit and Itay Segev

