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
void send_icmp_packet(int sock, struct sockaddr_in *dest, int ttl) {
    char packet[64];
    struct icmphdr *icmp_hdr = (struct icmphdr *)packet;

    memset(packet, 0, sizeof(packet));

    // Fill ICMP Header
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->un.echo.id = getpid();
    icmp_hdr->un.echo.sequence = ttl;

    // Calculate checksum
    icmp_hdr->checksum = calculate_checksum(packet, sizeof(packet));

    // Set the TTL
    setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    // Send the packet
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)dest, sizeof(*dest)) < 0) {
        perror("sendto");
    }
}
int receive_icmp_response(int sock, struct timeval *start_time) {
    char buffer[1024];
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
    double rtt = (end_time.tv_sec - start_time->tv_sec) * 1000.0 + (end_time.tv_usec - start_time->tv_usec) / 1000.0;

    struct iphdr *ip_hdr = (struct iphdr *)buffer;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + (ip_hdr->ihl * 4));

    if (icmp_hdr->type == ICMP_TIME_EXCEEDED || icmp_hdr->type == ICMP_ECHOREPLY) {
        printf("%s (RTT: %.2f ms)\n", inet_ntoa(recv_addr.sin_addr), rtt);
        if (icmp_hdr->type == ICMP_ECHOREPLY) {
            return 1;
        } 
        else {
            return 0;
        }
    }

    return 0;
}
void traceroute(const char *target) {
    int send_sock, recv_sock;
    struct sockaddr_in dest_addr;
    struct timeval timeout = {2, 0}; 

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (!inet_aton(target, &dest_addr.sin_addr)) {
        perror("inet_aton");
        exit(EXIT_FAILURE);
    }


    send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
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

    
    for (int ttl = 1; ttl <= 30; ttl++) {
        printf("TTL=%d: ", ttl);

        struct timeval start_time;
        gettimeofday(&start_time, NULL);

        send_icmp_packet(send_sock, &dest_addr, ttl);
        int status = receive_icmp_response(recv_sock, &start_time);

        if (status == 1) {
            printf("Destination reached.\n");
            break;
        } else if (status == -1) {
            printf("* (timeout)\n");
        }
    }

    close(send_sock);
    close(recv_sock);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s -a <address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *target_address = NULL;
    int opt;

    // Parse command-line options
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

    // Validate that target_address is provided
    if (target_address == NULL) {
        fprintf(stderr, "Error: Target address must be specified with -a\n");
        return 1;
    }

    // Call traceroute function with the provided address
    traceroute(target_address);
    return 0;
}

