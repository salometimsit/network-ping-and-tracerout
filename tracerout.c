#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>

#define PACKETSIZE 64
#define MAX_HOPS 30
#define TRIES_PER_HOP 3
#define RECV_TIMEOUT 1

struct packet {
    struct icmphdr hdr;
    char msg[PACKETSIZE - sizeof(struct icmphdr)];
};

volatile sig_atomic_t keep_running = 1;
char *dest_addr = NULL;

void signal_handler(int signum) {
    keep_running = 0;
}

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

int send_probe(int sd, struct sockaddr_in *addr, int ttl, int seq) {
    struct packet pckt;
    
    // Set TTL for this probe
    if (setsockopt(sd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
        perror("setsockopt ttl");
        return -1;
    }

    // Prepare ICMP packet
    memset(&pckt, 0, sizeof(pckt));
    pckt.hdr.type = ICMP_ECHO;
    pckt.hdr.code = 0;
    pckt.hdr.un.echo.id = htons(getpid());
    pckt.hdr.un.echo.sequence = htons(seq);
    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

    return sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr*)addr, sizeof(*addr));
}

double process_reply(void *buf, int bytes, struct sockaddr_in *from) {
    struct iphdr *ip = (struct iphdr*)buf;
    struct icmphdr *icmp = (struct icmphdr*)(buf + ip->ihl * 4);
    
    char src_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(from->sin_addr), src_addr, INET_ADDRSTRLEN);
    
    struct timeval recv_time;
    gettimeofday(&recv_time, NULL);
    
    return (double)recv_time.tv_usec / 1000.0;
}

int main(int argc, char *argv[]) {
    if (argc != 3 || strcmp(argv[1], "-a") != 0) {
        printf("Usage: %s -a <destination>\n", argv[0]);
        exit(1);
    }
    
    dest_addr = argv[2];
    struct hostent *hname;
    struct sockaddr_in addr;
    struct protoent *proto;
    
    signal(SIGINT, signal_handler);
    
    proto = getprotobyname("ICMP");
    if (!proto) {
        perror("getprotobyname");
        exit(1);
    }
    hname = gethostbyname(dest_addr);
    if (!hname) {
        fprintf(stderr, "Could not resolve hostname %s\n", dest_addr);
        exit(1);
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = hname->h_addrtype;
    addr.sin_port = 0;
    memcpy(&addr.sin_addr.s_addr, hname->h_addr_list[0], hname->h_length);
    
    printf("traceroute to %s (%s), %d hops max\n", 
           dest_addr, 
           inet_ntoa(addr.sin_addr), 
           MAX_HOPS);
    
    int send_sd = socket(AF_INET, SOCK_RAW, proto->p_proto);
    if (send_sd < 0) {
        perror("socket");
        exit(1);
    }
    int recv_sd = socket(AF_INET, SOCK_RAW, proto->p_proto);
    if (recv_sd < 0) {
        perror("socket");
        exit(1);
    }
    struct timeval tv;
    tv.tv_sec = RECV_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(recv_sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    for (int ttl = 1; ttl <= MAX_HOPS && keep_running; ttl++) {
        printf("%2d ", ttl);
        
        char current_addr[INET_ADDRSTRLEN] = {0};
        int reached_dest = 0;
        
        for (int try = 0; try < TRIES_PER_HOP; try++) {
            if (send_probe(send_sd, &addr, ttl, try + 1) < 0) {
                printf(" *");
                continue;
            }
            
            struct sockaddr_in recv_addr;
            socklen_t recv_addr_len = sizeof(recv_addr);
            char recv_buf[512];
            
            int bytes = recvfrom(recv_sd, recv_buf, sizeof(recv_buf), 0,
                               (struct sockaddr*)&recv_addr, &recv_addr_len);
            
            if (bytes < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    printf(" *");
                    continue;
                }
                perror("recvfrom");
                continue;
            }
            
            char hop_addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(recv_addr.sin_addr), hop_addr, INET_ADDRSTRLEN);
            
            if (strlen(current_addr) == 0) {
                strcpy(current_addr, hop_addr);
                printf(" %s", hop_addr);
            }
            
            double rtt = process_reply(recv_buf, bytes, &recv_addr);
            printf(" %.3fms", rtt);
            if (strcmp(hop_addr, inet_ntoa(addr.sin_addr)) == 0) {
                reached_dest = 1;
            }
        }
        
        printf("\n");
        
        if (reached_dest) {
            break;
        }
    }
    
    close(send_sd);
    close(recv_sd);
    return 0;
}
