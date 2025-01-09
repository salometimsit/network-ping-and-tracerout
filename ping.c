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

#define PACKETSIZE 64
#define MAX_PACKETS 100

/**
 * Method Goal:
 *      Represents an ICMP packet with a header and a message
 */
struct packet {
    struct icmphdr hdr;
    char msg[PACKETSIZE - sizeof(struct icmphdr)];
};


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

/**
 * @brief Handles termination signals (e.g., SIGINT or SIGTERM).
 * @param signum Signal number
 */
void signal_handler(int signum) {
    keep_running = 0;
}

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
/**
 * Methods Goal:
 *      receives a pointer to the buffer containing the packet 
 *      and also the number of bytes in the packet 
 *      and it processes a received ICMP packet and calculates round-trip time (RTT).
 */
void process(void *buf, int bytes) {
    struct iphdr *ip = (struct iphdr*)buf;
    struct icmphdr *icmp = (struct icmphdr*)(buf + ip->ihl * 4);
    struct timeval recv_time;
    display(buf, bytes);
    
    gettimeofday(&recv_time, NULL);

    if (icmp->type == ICMP_ECHOREPLY && icmp->un.echo.id == htons(pid)) {
        int seq = ntohs(icmp->un.echo.sequence) - 1;
        if (seq >= 0 && seq < MAX_PACKETS) {
            shared->received_packets++;
            
            double rtt = (recv_time.tv_sec - shared->send_times[seq].tv_sec) * 1000.0 +
                        (recv_time.tv_usec - shared->send_times[seq].tv_usec) / 1000.0;
            
            // Update statistics
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
}
/**
 * Methods Goal:
 *          Listens for ICMP Echo Reply packets and processes them.
 *          this function is connected to the process function
 */
void listener(void) {
    int sd;
    struct sockaddr_in addr;
    unsigned char buf[1024];

    sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
    if (sd < 0) {
        perror("socket");
        exit(1);
    }

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (keep_running && shared->received_packets < loops) {
        int bytes, len = sizeof(addr);
        bzero(buf, sizeof(buf));
        bytes = recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr*)&addr, &len);
        if (bytes > 0) {
            process(buf, bytes);
        }
    }
    close(sd);
    exit(0);
}
/**
 * Methods Goal:
 *          receives a pointer to the destenantion address
 *          and sends ICMP Echo Request packets and records send times.
 *          this function is the main method that connects all the dots
 */
void ping(struct sockaddr_in *addr) {
    int sd = socket(PF_INET, SOCK_RAW, proto->p_proto);
    if (sd < 0) {
        perror("socket");
        return;
    }

    if (setsockopt(sd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
        perror("set TTL option");
    }

    printf("PING %s (%s): %d data bytes\n", 
           address, 
           inet_ntoa(addr->sin_addr),
           PACKETSIZE - sizeof(struct icmphdr));

    struct packet pckt;
    int sequence = 0;

    while (keep_running && sequence < loops) {
        bzero(&pckt, sizeof(pckt));
        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.code = 0;
        pckt.hdr.un.echo.id = htons(pid);
        pckt.hdr.un.echo.sequence = htons(sequence + 1);

        // Store send time
        gettimeofday(&shared->send_times[sequence], NULL);

        for (int j = 0; j < sizeof(pckt.msg) - 1; j++) {
            pckt.msg[j] = j + '0';
        }

        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

        if (sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)addr, sizeof(*addr)) <= 0) {
            perror("sendto");
        } else {
            shared->sent_packets++;
            sequence++;
        }

        sleep(sleepTime);
    }

    close(sd);
}


/**
 * Methods Goal: 
 *          receives argc and argv command lind arguments 
 *          this is the function that handles argument parsing, setup, and execution.
 * Return: 
 *      Exit status
 */
int main(int argc, char *argv[]) {
    struct hostent *hname;
    struct sockaddr_in addr;

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
    proto = getprotobyname("ICMP");
    if (!proto) {
        perror("getprotobyname");
        exit(1);
    }

    // Resolve hostname
    hname = gethostbyname(address);
    if (!hname) {
        fprintf(stderr, "Could not resolve hostname %s\n", address);
        exit(1);
    }

    // Set up address structure
    bzero(&addr, sizeof(addr));
    addr.sin_family = hname->h_addrtype;
    addr.sin_port = 0;
    memcpy(&addr.sin_addr.s_addr, hname->h_addr_list[0], hname->h_length);

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
        ping(&addr);
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
