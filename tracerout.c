#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <errno.h>
#include <bits/getopt_core.h>

// Constants for program configuration
#define MAX_HOPS 30
#define TRIES_PER_HOP 3
#define TIMEOUT_SECS 2
#define PACKET_SIZE 64
#define BUFFER_SIZE 1024

/**
 * Method Goal: 
 *  Calculate the checksum for IP and ICMP packets
 * What the Method Does:
 * - Takes a buffer of data and its length
 * - Performs a 16-bit one's complement sum over the buffer
 * - Handles odd-length buffers
 * - Folds the 32-bit sum into 16 bits
 * Return:
 * - 16-bit checksum value for the packet
 */
unsigned short calculate_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

/**
 * Method Goal: 
 *  Create and send an ICMP Echo Request packet with custom IP header
 * What the Method Does:
 * - Creates a packet buffer of defined size
 * - Creates custom IP header
 * - Fills ICMP header fields
 * - Calculates and sets checksums for both headers
 * - Sends packet to destination
 * Return: void
 */
void send_icmp_packet(int sock, struct sockaddr_in *dest, int ttl, int seq) {
    // Increase packet size to accommodate both IP and ICMP headers
    char packet[PACKET_SIZE + sizeof(struct iphdr)];
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct iphdr));

    // Clear the packet buffer
    memset(packet, 0, sizeof(packet));

    // Fill in the IP header
    ip_hdr->version = 4;  // IPv4
    ip_hdr->ihl = 5;      // 5 * 32-bit words = 20 bytes (standard IP header size)
    ip_hdr->tos = 0;
    ip_hdr->tot_len = sizeof(struct iphdr) + PACKET_SIZE;
    ip_hdr->id = htons(getpid());
    ip_hdr->frag_off = 0;
    ip_hdr->ttl = ttl;
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->check = 0;    // Will be filled by kernel
    ip_hdr->saddr = INADDR_ANY;  // Source address
    ip_hdr->daddr = dest->sin_addr.s_addr;  // Destination address
    
    // Calculate IP header checksum
    ip_hdr->check = calculate_checksum(ip_hdr, sizeof(struct iphdr));

    // Fill in the ICMP header
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->un.echo.id = getpid();
    icmp_hdr->un.echo.sequence = seq;

    // Calculate ICMP checksum
    icmp_hdr->checksum = calculate_checksum(icmp_hdr, PACKET_SIZE);

    // Tell the kernel we'll provide the IP header
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        return;
    }

    if (sendto(sock, packet, ip_hdr->tot_len, 0, (struct sockaddr *)dest, sizeof(*dest)) < 0) {
        perror("sendto");
    }
}

/**
 * Method Goal: 
 *  Receive and process ICMP responses
 * What the Method Does:
 * - Waits for incoming ICMP packet
 * - Handles timeout conditions
 * - Calculates Round Trip Time (RTT)
 * - Processes both TIME_EXCEEDED and ECHO_REPLY messages
 * Return:
 * - 1 if destination reached (ECHO_REPLY)
 * - 0 if intermediate hop (TIME_EXCEEDED)
 * - -1 on timeout or error
 */
int receive_icmp_response(int sock, struct timeval *start_time, double *rtt, char *addr_str) {
    char buffer[BUFFER_SIZE];
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);
    struct timeval end_time;

    int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&recv_addr, &addr_len);
    if (bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -1; // Timeout
        } else {
            perror("recvfrom");
            return -1;
        }
    }

    gettimeofday(&end_time, NULL);
    *rtt = (end_time.tv_sec - start_time->tv_sec) * 1000.0 + 
           (end_time.tv_usec - start_time->tv_usec) / 1000.0;

    struct iphdr *ip_hdr = (struct iphdr *)buffer;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + (ip_hdr->ihl * 4));

    if (icmp_hdr->type == ICMP_TIME_EXCEEDED || icmp_hdr->type == ICMP_ECHOREPLY) {
        strcpy(addr_str, inet_ntoa(recv_addr.sin_addr));
        if (icmp_hdr->type == ICMP_ECHOREPLY) {
            return 1;
        } 
        return 0;
    }

    return -1;
}

/**
 * Method Goal:
 *   Implement main traceroute functionality
 * What the Method Does:
 * - Sets up destination address structure
 * - Creates separate sockets for sending and receiving
 * - Sets socket timeout
 * - For each TTL (1-30):
 *   - Sends 3 ICMP packets
 *   - Processes responses
 *   - Displays results in formatted output
 * Return: void
 */
void traceroute(const char *target) {
    int send_sock, recv_sock;
    struct sockaddr_in dest_addr;
    struct timeval timeout = {TIMEOUT_SECS, 0}; 

    printf("traceroute to %s, %d hops max\n", target, MAX_HOPS);

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (!inet_aton(target, &dest_addr.sin_addr)) {
        perror("inet_aton");
        exit(EXIT_FAILURE);
    }

    // Use IPPROTO_RAW for custom IP header
    send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_sock < 0) {
        perror("send socket");
        exit(EXIT_FAILURE);
    }

    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_sock < 0) {
        perror("recv socket");
        exit(EXIT_FAILURE);
    }
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    for (int ttl = 1; ttl <= MAX_HOPS; ttl++) {
        printf("%2d  ", ttl);
        int reached = 0;
        char last_addr[INET_ADDRSTRLEN] = {0};
        
        for (int try = 0; try < TRIES_PER_HOP; try++) {
            struct timeval start_time;
            double rtt;
            char addr_str[INET_ADDRSTRLEN];
            
            gettimeofday(&start_time, NULL);
            send_icmp_packet(send_sock, &dest_addr, ttl, (ttl * TRIES_PER_HOP) + try);
            int status = receive_icmp_response(recv_sock, &start_time, &rtt, addr_str);

            if (status == -1) {
                printf("* ");
            } else {
                if (try == 0 || strcmp(last_addr, addr_str) != 0) {
                    printf("%s ", addr_str);
                    strcpy(last_addr, addr_str);
                }
                printf("%.3fms ", rtt);
                if (status == 1) {
                    reached = 1;
                }
            }
        }
        printf("\n");
        
        if (reached) {
            break;
        }
    }

    close(send_sock);
    close(recv_sock);
}

/**
 * Method Goal: 
 *  Program entry point and argument processing
 * What the Method Does:
 * - Validates command line arguments
 * - Parses -a option for target address
 * - Calls traceroute function
 * Return:
 * - 0 on success
 * - 1 on error
 */
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s -a <address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *target_address = NULL;
    int opt;
  
    while ((opt = getopt(argc, argv, "a:")) != -1) {
        switch (opt) {
            case 'a':
                target_address = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s -a <address>\n", argv[0]);
                return 1;
        }
    }
 
    if (target_address == NULL) {
        fprintf(stderr, "Error: Target address must be specified with -a\n");
        return 1;
    }

    traceroute(target_address);
    return 0;
}
