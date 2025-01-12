#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/mman.h>
#include <float.h>
#include <netinet/icmp6.h>

#define PACKETSIZE 64
#define MAX_PACKETS 100

/**
 * Method Goal:
 *      Represents an ICMP packet with a header and a message
 */
struct packet {
    union {
        struct icmphdr icmp4;
        struct icmp6_hdr icmp6;
    } hdr;
    char msg[PACKETSIZE - sizeof(struct icmphdr)];
};

//--------------------------------------------------------------------------------------------
/**
 * Method Goal:
 *      Represents shared data used for statistics across multiple processes.
 */
struct shared_data {
    int sent_packets;
    int received_packets;
    double min_time;        //of RTT
    double max_time;
    double total_time;
    struct timeval send_times[MAX_PACKETS];
};
//--------------------------------------------------------------------------------------------
// Defining global variables
volatile sig_atomic_t keep_running = 1;
struct shared_data *shared = NULL;
int pid = -1;
int loops = 4;
char *address = "0.0.0.0";
int ttl = 56;
int sleepTime = 1;
int ip_v = 4;
struct protoent *proto = NULL;
//--------------------------------------------------------------------------------------------
/**
 * @brief Handles termination signals (e.g., SIGINT or SIGTERM).
 * @param signum Signal number
 */
void signal_handler(int signum) {
    keep_running = 0;
}

//--------------------------------------------------------------------------------------------
/**
 * Method Goals:
*      Creates and initializes shared memory for storing statistics.
* Return:
 *      Pointer to shared_data structure
 */
struct shared_data* shared_mem() {
    void *ptr = mmap(NULL, sizeof(struct shared_data),PROT_READ | PROT_WRITE,MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    memset(ptr, 0, sizeof(struct shared_data));
    return (struct shared_data*)ptr;
}

//--------------------------------------------------------------------------------------------
/**
 * Method Goals:
 *      receives a poointer to the packet and the length and computes the checksum for an ICMP packet.
 * Returns:
 *         Checksum value
 */
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

//--------------------------------------------------------------------------------------------
/**
 * Method Goals:
 *         receives a pointer to the buffer that contains the packet and also receives number of bytes in the packet
 *          and it displays IPv4 packet details.
 */
void displayipv4(void *buf, int bytes) {
    struct iphdr *ip = (struct iphdr *)buf;
    struct icmphdr *icmp = (struct icmphdr *)(buf + ip->ihl * 4);
    
    printf("\n-----ipv4------\n");
    printf("-------------------\n");
    
    char sourceIPADDReadable[INET_ADDRSTRLEN];
    char destinationIPADDReadable[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, sourceIPADDReadable, sizeof(sourceIPADDReadable));
    inet_ntop(AF_INET, &ip->daddr, destinationIPADDReadable, sizeof(destinationIPADDReadable));
    
    printf("Source: %s\n", sourceIPADDReadable);
    printf("Destination: %s\n", destinationIPADDReadable);
    printf("Version: IPv%d\nHeader Size: %d bytes\nPacket Size: %d bytes\nProtocol: %d\nTTL: %d\n",
           ip->version, ip->ihl * 4, ntohs(ip->tot_len), ip->protocol, ip->ttl);

    if (icmp->type == ICMP_ECHOREPLY && icmp->un.echo.id == htons(pid)) {
        printf("ICMP Echo Reply:\n");
        printf("Type: %d\nCode: %d\nChecksum: %d\nID: %d\nSequence: %d\n",
               icmp->type, icmp->code, icmp->checksum,
               ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
    }
    printf("-------------------\n");
}

//--------------------------------------------------------------------------------------------
/**
 * Method Goals:
 *         receives a pointer to the buffer that contains the packet and also receives number of bytes in the packet
 *          and it displays IPv6 packet details.
 */
void displayipv6(void *buf, int bytes) {
    printf("-----ipv6------\n");
    struct ip6_hdr *ip = (struct ip6_hdr *)buf;
    struct icmphdr *icmp = (struct icmphdr *)(buf + sizeof(struct ip6_hdr));
    
    printf("-------------------\n");
    
    char sourceIPADDReadable[INET6_ADDRSTRLEN] = {'\0'};
    char destinationIPADDReadable[INET6_ADDRSTRLEN] = {'\0'};
    inet_ntop(AF_INET6, &ip->ip6_src, sourceIPADDReadable, sizeof(sourceIPADDReadable));
    inet_ntop(AF_INET6, &ip->ip6_dst, destinationIPADDReadable, sizeof(destinationIPADDReadable));
    
    printf("Source: %s\n", sourceIPADDReadable);
    printf("Destination: %s\n", destinationIPADDReadable);
    printf("Version: IPv6\n");
    printf("Traffic Class: %d\n", (ip->ip6_ctlun.ip6_un1.ip6_un1_flow >> 20) & 0xff);
    printf("Flow Label: %d\n", ip->ip6_ctlun.ip6_un1.ip6_un1_flow & 0xfffff);
    printf("Payload Length: %d\n", ntohs(ip->ip6_ctlun.ip6_un1.ip6_un1_plen));
    printf("Next Header: %d\n", ip->ip6_ctlun.ip6_un1.ip6_un1_nxt);
    printf("Hop Limit: %d\n", ip->ip6_ctlun.ip6_un1.ip6_un1_hlim);

    if (icmp->un.echo.id == htons(pid)) {
        printf("ICMP: type[%d/%d] checksum[%d] id[%d] seq[%d]\n", 
               icmp->type, icmp->code, icmp->checksum,
               ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence));
    }
    printf("-------------------\n");
}

//--------------------------------------------------------------------------------------------
/**
 * Methods Goal:
 *          receives a pointer to the buffer where the packet is located, 
 *          and number of bytes in the packet
 *          and then displays packet details based on IP version.
 */
void display(void *buf, int bytes) {
    if (ip_v == 4) {
        displayipv4(buf, bytes);
    } else if (ip_v == 6) {
        displayipv6(buf, bytes);
    } else {
        printf("Unknown IP version\n");
    }
}

//--------------------------------------------------------------------------------------------
/**
 * Methods Goal:
 *      receives a pointer to the buffer containing the packet 
 *      and also the number of bytes in the packet 
 *      and it processes a received ICMP packet and calculates round-trip time (RTT).
 */
void process(void *buf, int bytes) {
    struct timeval recv_time;
    display(buf, bytes);
    
    gettimeofday(&recv_time, NULL);

    if (ip_v == 4) {
        struct iphdr *ip = (struct iphdr*)buf;
        struct icmphdr *icmp = (struct icmphdr*)(buf + ip->ihl * 4);
        
        if (icmp->type == ICMP_ECHOREPLY && icmp->un.echo.id == htons(pid)) {
            int seq = ntohs(icmp->un.echo.sequence) - 1;
            if (seq >= 0 && seq < MAX_PACKETS) {
                shared->received_packets++;
                
                double rtt = (recv_time.tv_sec - shared->send_times[seq].tv_sec) * 1000.0 +
                            (recv_time.tv_usec - shared->send_times[seq].tv_usec) / 1000.0;
                
                if (shared->received_packets == 1 || rtt < shared->min_time)
                    shared->min_time = rtt;
                if (rtt > shared->max_time)
                    shared->max_time = rtt;
                shared->total_time += rtt;
                
                printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
                       bytes - sizeof(struct iphdr),
                       inet_ntoa(*(struct in_addr*)&ip->saddr),
                       seq + 1,
                       ip->ttl,
                       rtt);
            }
        }
    } else { // IPv6
        struct ip6_hdr *ip6 = (struct ip6_hdr*)buf;
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr*)(buf + sizeof(struct ip6_hdr));
        
        if (icmp6->icmp6_type == ICMP6_ECHO_REPLY && icmp6->icmp6_id == htons(pid)) {
            int seq = ntohs(icmp6->icmp6_seq) - 1;
            if (seq >= 0 && seq < MAX_PACKETS) {
                shared->received_packets++;
                
                double rtt = (recv_time.tv_sec - shared->send_times[seq].tv_sec) * 1000.0 +
                            (recv_time.tv_usec - shared->send_times[seq].tv_usec) / 1000.0;
                
                if (shared->received_packets == 1 || rtt < shared->min_time)
                    shared->min_time = rtt;
                if (rtt > shared->max_time)
                    shared->max_time = rtt;
                shared->total_time += rtt;
                
                char sourceIPADDReadable[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &ip6->ip6_src, sourceIPADDReadable, INET6_ADDRSTRLEN);
                
                printf("%d bytes from %s: icmp_seq=%d hlim=%d time=%.3f ms\n",
                       bytes - sizeof(struct ip6_hdr),
                       sourceIPADDReadable,
                       seq + 1,
                       ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim,
                       rtt);
            }
        }
    }
}
//--------------------------------------------------------------------------------------------
/**
 * Methods Goal:
 *          Listens for ICMP Echo Reply packets and processes them.
 *          this function is connected to the process function
 */
void listener(void) {
    int sd;
    unsigned char buf[1024];
    
    if (ip_v == 6) {
        sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    } else {
        sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
    }
    
    if (sd < 0) {
        perror("socket");
        exit(1);
    }

    // For IPv6, we need to join the all-nodes multicast group
    if (ip_v == 6) {
        struct icmp6_filter filter;
        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
        setsockopt(sd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (keep_running && shared->received_packets < loops) {
        int bytes;
        if (ip_v == 6) {
            struct sockaddr_in6 addr6;
            socklen_t len = sizeof(addr6);
            bytes = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr*)&addr6, &len);
        } else {
            struct sockaddr_in addr4;
            socklen_t len = sizeof(addr4);
            bytes = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr*)&addr4, &len);
        }
        
        if (bytes > 0) {
            process(buf, bytes);
        }
        sleep(sleepTime);
    }
    close(sd);
    exit(0);
}

//--------------------------------------------------------------------------------------------
/**
 * Methods Goal:
 *          receives a pointer to the destenantion address
 *          and sends ICMP Echo Request packets and records send times.
 *          this function is the main method that connects all the dots
 */
void ping(void *addr) {
    int sd = -1;
    struct packet pckt;
    int sequence = 0;
    
    if (ip_v == 6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        sd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (sd < 0) {
            perror("socket IPv6");
            return;
        }
        
        // Set IPv6 socket options
        int on = 1;
        if (setsockopt(sd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)) < 0) {
            perror("setsockopt IPV6_RECVHOPLIMIT");
        }
        
        // Set hop limit
        if (setsockopt(sd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) != 0) {
            perror("set hop limit option");
        }
        
        char addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr6->sin6_addr, addr_str, INET6_ADDRSTRLEN);
        printf("PING %s: %d data bytes\n", addr_str, PACKETSIZE - sizeof(struct icmp6_hdr));
        
        while (keep_running && sequence < loops) {
            gettimeofday(&shared->send_times[sequence], NULL);
            
            // Initialize ICMPv6 header
            memset(&pckt, 0, sizeof(pckt));
            pckt.hdr.icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
            pckt.hdr.icmp6.icmp6_code = 0;
            pckt.hdr.icmp6.icmp6_id = htons(pid);
            pckt.hdr.icmp6.icmp6_seq = htons(sequence + 1);
            
            // Fill payload
            for (int j = 0; j < sizeof(pckt.msg) - 1; j++) {
                pckt.msg[j] = j + '0';
            }
            
            if (sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)addr6, sizeof(*addr6)) <= 0) {
                perror("sendto IPv6");
            } else {
                shared->sent_packets++;
                sequence++;
            }
            sleep(sleepTime);
        }
        } else {
        // Original IPv4 code remains the same
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        sd = socket(AF_INET, SOCK_RAW, proto->p_proto);
        if (sd < 0) {
            perror("socket IPv4");
            return;
        }

        if (setsockopt(sd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
            perror("set TTL option");
        }

        printf("PING %s (%s): %d data bytes\n", 
               address, 
               inet_ntoa(addr4->sin_addr),
               PACKETSIZE - sizeof(struct icmphdr));

        while (keep_running && sequence < loops) {
            gettimeofday(&shared->send_times[sequence], NULL);

            pckt.hdr.icmp4.type = ICMP_ECHO;
            pckt.hdr.icmp4.code = 0;
            pckt.hdr.icmp4.un.echo.id = htons(pid);
            pckt.hdr.icmp4.un.echo.sequence = htons(sequence + 1);

            for (int j = 0; j < sizeof(pckt.msg) - 1; j++) {
                pckt.msg[j] = j + '0';
            }

            pckt.hdr.icmp4.checksum = 0;
            pckt.hdr.icmp4.checksum = checksum(&pckt, sizeof(pckt));

            if (sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)addr4, sizeof(*addr4)) <= 0) {
                perror("sendto IPv4");
            } else {
                shared->sent_packets++;
                sequence++;
            }
            sleep(sleepTime);
        }
    }
    close(sd);
}

//--------------------------------------------------------------------------------------------
/**
 * Methods Goal: 
 *          receives argc and argv command lind arguments 
 *          this is the function that handles argument parsing, setup, and execution.
 * Return: 
 *      Exit status
 */
int main(int argc, char *argv[]) {
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
    void* addr_ptr;

    if (argc < 2) {
        printf("Usage: %s <hostname> [-c count] [-f] [-t 4|6]\n", argv[0]);
        exit(1);
    }

    // Create shared memory and initialize
    shared = shared_mem();
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            address = argv[i + 1];
            i++;
        }
        else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            loops = atoi(argv[i + 1]);
            if (loops <= 0 || loops > MAX_PACKETS) {
                printf("Invalid count value. Using default: 4\n");
                loops = 4;
            }
            i++;
        }
        else if (strcmp(argv[i], "-f") == 0) {
            sleepTime = 0;
        }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "4") == 0) {
                ip_v = 4;
            } else if (strcmp(argv[i + 1], "6") == 0) {
                ip_v = 6;
            } else {
                fprintf(stderr, "Unknown IP version\n");
                return -1;
            }
            i++;
        }
    }

    // Get ICMP protocol
    if (ip_v == 4) {
        proto = getprotobyname("ICMP");
    } else if (ip_v == 6) {
        // Try different protocol names for IPv6
        proto = getprotobyname("ipv6-icmp");
        if (!proto) {
            proto = getprotobyname("icmpv6");
        }
        if (!proto) {
            // If protocol lookup fails, use the known protocol number for ICMPv6
            static struct protoent icmp6_proto = {
                .p_name = "ipv6-icmp",
                .p_proto = IPPROTO_ICMPV6,
                .p_aliases = NULL
            };
            proto = &icmp6_proto;
        }
    }
    
    if (!proto) {
        perror("getprotobyname");
        exit(1);
    }

    // Set up address structure based on IP version
    if (ip_v == 6) {
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, address, &addr6.sin6_addr) <= 0) {
            fprintf(stderr, "Invalid IPv6 address\n");
            exit(1);
        }
        addr_ptr = &addr6;
    } else {
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        if (inet_pton(AF_INET, address, &addr4.sin_addr) <= 0) {
            fprintf(stderr, "Invalid IPv4 address\n");
            exit(1);
        }
        addr_ptr = &addr4;
    }

    // Get process ID
    pid = getpid();

    // Fork and run listener and ping
    pid_t child_pid = fork();
    if (child_pid < 0) {
        perror("fork");
        return 1;
    }

    if (child_pid == 0) {
        listener();
    } else {
        ping(addr_ptr);
        sleep(1);  // Give listener time to process final packets
        kill(child_pid, SIGTERM);
        wait(NULL);

        // Print statistics
        printf("\n--- %s ping statistics ---\n", address);
        if (shared->sent_packets > 0) {
            printf("%d packets transmitted, %d received, %.1f%% packet loss\n",
                   shared->sent_packets, 
                   shared->received_packets,
                   100.0 * (shared->sent_packets - shared->received_packets) / shared->sent_packets);
            
            if (shared->received_packets > 0) {
                double avg_time = shared->total_time / shared->received_packets;
                printf("round-trip min/avg/max = %.3f/%.3f/%.3f ms\n",
                       shared->min_time, avg_time, shared->max_time);
            }
        }

        // Clean up shared memory
        munmap(shared, sizeof(struct shared_data));
    }

    return 0;
}
