#include <stdio.h>
#include <sys/types.h>    
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <getopt.h>
#include <math.h>
#include <netdb.h> 

// Constants
#define MAX_REQUESTS 4
#define TIMEOUT 1000
#define BUFFER_SIZE 1024
#define SLEEP_TIME 1
#define MAX_RETRY 3

// Global variables
unsigned int packets_sent = 0;
unsigned int packets_received = 0;
unsigned int rtt_count = 0;
float *rtts = NULL;

// Calculate checksum for ICMP packets
unsigned short calculate_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Check IPv6 availability
int check_ipv6() {
    int trysocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (trysocket < 0) {
        return 0;
    }
    
    struct sockaddr_in6 test_addr;
    memset(&test_addr, 0, sizeof(test_addr));
    test_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::1", &test_addr.sin6_addr);
    test_addr.sin6_port = htons(0);
    
    int result = connect(trysocket, (struct sockaddr *)&test_addr, sizeof(test_addr));
    close(trysocket);
    
    return result == 0;
}

// Display ping statistics
void display(float *result, char *addr) {
    printf("\n--- %s ping statistics ---\n", addr);
    printf("%u packets transmitted, %u received, %.1f%% packet loss\n",
           packets_sent, packets_received,
           100.0 * (packets_sent - packets_received) / packets_sent);

    if (packets_received > 0) {
        float min = result[0];
        float max = result[0];
        float sum = result[0];
        for (unsigned int i = 1; i < packets_received; i++) {
            if (result[i] < min) min = result[i];
            if (result[i] > max) max = result[i];
            sum += result[i];
        }
        printf("rtt min/avg/max = %.2f/%.2f/%.2f ms\n",
               min, sum/packets_received, max);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s -a <address> -t <type> [-c <count>] [-f]\n", argv[0]);
        return 1;
    }

    int ping_count = MAX_REQUESTS;
    int flood_mode = 0;
    int ip_v = 0;
    char *target_address = NULL;
    int opt;
    
    while ((opt = getopt(argc, argv, "a:t:c:f")) != -1) {
        switch (opt) {
            case 'a':
                target_address = optarg;
                break;
            case 't':
                ip_v = atoi(optarg);
                if (ip_v != 4 && ip_v != 6) {
                    fprintf(stderr, "Error: Invalid type '%s'. Use 4 for IPv4 or 6 for IPv6.\n", optarg);
                    return 1;
                }
                break;
            case 'c':
                ping_count = atoi(optarg);
                break;
            case 'f':
                flood_mode = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s -a <address> -t <type> [-c <count>] [-f]\n", argv[0]);
                return 1;
        }
    }
    if (ip_v == 0) {
        fprintf(stderr, "Error: Address and IP version are required.\n");
        return 1;
    }

    if (ip_v == 6) {
        if (!check_ipv6()) {
            fprintf(stderr, "Error: IPv6 is not available on this system\n");
            return 1;
        }
    }
    
    rtts = (float *)malloc(ping_count * sizeof(float));
    if (rtts == NULL) {
        perror("Failed to allocate memory");
        return 1;
    }

    int sock = -1;
    struct sockaddr_storage dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    socklen_t addr_len;

    if (ip_v == 6) {
        sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (sock < 0) {
            perror("Failed to create socket");
            free(rtts);
            return 1;
        }

        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&dest_addr;
        addr6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, target_address, &addr6->sin6_addr) <= 0) {
            fprintf(stderr, "Error: Invalid IPv6 address\n");
            close(sock);
            free(rtts);
            return 1;
        }
        addr_len = sizeof(struct sockaddr_in6);
    } 
    else {
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) {
            perror("Failed to create socket");
            if (errno == EACCES || errno == EPERM) {
                fprintf(stderr, "You need to run the program with sudo.\n");
            }
            free(rtts);
            return 1;
        }

        struct sockaddr_in *addr4 = (struct sockaddr_in *)&dest_addr;
        addr4->sin_family = AF_INET;
        if (inet_pton(AF_INET, target_address, &addr4->sin_addr) <= 0) {
            fprintf(stderr, "Error: Invalid IPv4 address\n");
            close(sock);
            free(rtts);
            return 1;
        }
        addr_len = sizeof(struct sockaddr_in);
    }

    struct pollfd fds[1];
    fds[0].fd = sock;
    fds[0].events = POLLIN;

    char *msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$^&*()_+{}|:<>?~`-=[]',.  ";
    int payload_size = strlen(msg+ 1) ;
    char packet_buffer[BUFFER_SIZE] = {0};
    int retry_count = 0;
    int sequence = 0;

    printf("PING %s with %d bytes of data:\n", target_address, payload_size);
    int max_packets = ping_count; 
    while (ping_count > 0 && packets_sent < max_packets) {
        memset(packet_buffer, 0, sizeof(packet_buffer));
        struct timeval start, end;
        ssize_t sent_bytes = 0;

        if (ip_v == 6) {
            struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)packet_buffer;
            icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
            icmp6->icmp6_code = 0;
            icmp6->icmp6_id = htons(getpid() & 0xFFFF);
            icmp6->icmp6_seq = htons(sequence);
            memcpy(packet_buffer + sizeof(struct icmp6_hdr), msg, payload_size);
            sent_bytes = sendto(sock, packet_buffer, sizeof(struct icmp6_hdr) + payload_size, 0,
                              (struct sockaddr *)&dest_addr, addr_len);
        }
        else {
            struct icmphdr *icmp4 = (struct icmphdr *)packet_buffer;
            icmp4->type = ICMP_ECHO;
            icmp4->code = 0;
            icmp4->un.echo.id = htons(getpid() & 0xFFFF);
            icmp4->un.echo.sequence = htons(sequence);
            memcpy(packet_buffer + sizeof(struct icmphdr), msg, payload_size);
            icmp4->checksum = calculate_checksum(packet_buffer, sizeof(struct icmphdr) + payload_size);
            sent_bytes = sendto(sock, packet_buffer, sizeof(struct icmphdr) + payload_size, 0,
                              (struct sockaddr *)&dest_addr, addr_len);
        }

        if (sent_bytes < 0) {
            if (errno == ENETUNREACH) {
                fprintf(stderr, "Error: Network is unreachable\n");
                break;
            }
            perror("Failed to send packet");
            continue;
        }
        packets_sent++;
        gettimeofday(&start, NULL);

        int poll_result = poll(fds, 1, TIMEOUT);
        if (poll_result == 0) {
            fprintf(stderr, "Request timeout for icmp_seq %d\n", sequence);
            continue;
        } else if (poll_result < 0) {
            perror("Poll failed");
            break;
        }

        if (fds[0].revents & POLLIN) {
            struct sockaddr_storage source_addr;
            socklen_t source_len = sizeof(source_addr);
            ssize_t received = recvfrom(sock, packet_buffer, sizeof(packet_buffer), 0,
                                      (struct sockaddr *)&source_addr, &source_len);
            if (received < 0) {
                perror("Failed to receive packet");
                continue;
            }

            gettimeofday(&end, NULL);
            float rtt = ((end.tv_sec - start.tv_sec) * 1000.0) +
                       ((end.tv_usec - start.tv_usec) / 1000.0);

            if (ip_v == 6) {
                struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)packet_buffer;
                if (icmp6->icmp6_type == ICMP6_ECHO_REPLY && ntohs(icmp6->icmp6_seq) == sequence) {
                    char src_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&source_addr)->sin6_addr,
                             src_str, sizeof(src_str));
                    printf("%d bytes from %s: icmp_seq=%d time=%.2f ms\n",
                           payload_size, src_str, ntohs(icmp6->icmp6_seq), rtt);
                    rtts[rtt_count++] = rtt;
                    packets_received++;
                    retry_count = 0;
                    ping_count--;
                    sequence++;
                }
            } else {
                struct iphdr *ip_header = (struct iphdr *)packet_buffer;
                struct icmphdr *icmp4 = (struct icmphdr *)(packet_buffer + ip_header->ihl * 4);
                if (icmp4->type == ICMP_ECHOREPLY) {
                    printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms\n",
                           payload_size, inet_ntoa(((struct sockaddr_in *)&source_addr)->sin_addr),
                           ntohs(icmp4->un.echo.sequence), ip_header->ttl, rtt);
                    rtts[rtt_count++] = rtt;
                    packets_received++;
                    retry_count = 0;
                    ping_count--;
                    sequence++;
                }
            }
        }

        if (!flood_mode) {
            sleep(SLEEP_TIME);
        } else {
            usleep(1000);
        }
    }

    display(rtts, target_address);
    free(rtts);
    close(sock);
    return 0;
}
