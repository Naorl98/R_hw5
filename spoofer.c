#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <string.h>

FILE *file;
struct in_addr src, dst;

struct icmpheader
{
    unsigned char type;
    unsigned char code;
    unsigned short int checksum;
    unsigned short int id;
    unsigned short int seq;
};

struct ipheader
{
    unsigned char ip_ihl : 4;
    unsigned char ip_ver : 4;
    unsigned char ip_tos;
    unsigned short int ip_len;
    unsigned short int ip_id;
    unsigned short int ip_flag : 3;
    unsigned short int ip_off : 13;
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short int ip_checksum;
    struct in_addr source_ip;
    struct in_addr dest_ip;
};

struct ethheader
{
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

struct udpheader
{
    u_int16_t udp_srcport;
    u_int16_t udp_destport;
    u_int16_t udp_len;
    u_int16_t udp_checksum;
};

unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}

void packet_spoof(struct ipheader *ip)
{
    struct sockaddr_in dest;
    int enable = 1;

    // sock creation
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1)
    {
        printf("error creating socket\n");
        return;
    }
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // information about dest
    dest.sin_family = AF_INET;
    dest.sin_addr = ip->dest_ip;

    // sends packet
    int send = sendto(sock, ip, ntohs(ip->ip_len), 0, (struct sockaddr *)&dest, sizeof(dest));
    if (send == -1)
    {
        printf("error sending packet\n");
        return;
    }
    printf("SUCCESSFULLY SENT A PACKET\n");
    close(sock);
}

int main()
{
    char buffer[1500];
    memset(buffer, 0, 1500);

    // FILL ICMP HEADER
    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
    icmp->type = 8; // 8 is request, 0 is reply

    icmp->checksum = 0;
    icmp->checksum = calculate_checksum((unsigned short *)icmp, sizeof(struct icmpheader));

    // // FILL UDP
    // struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    // char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader);
    // const char *msg = "Hello Server!\n";
    // //int data_len = strlen(msg);
    // //strncpy(data, msg, data_len);
    // udp->udp_srcport = htons(12345);
    // udp->udp_destport = htons(9090);
    // //udp->udp_len = htons(sizeof(struct udpheader) + data_len);
    // udp->udp_len = htons(sizeof(struct udpheader) + sizeof(ipheader));
    // udp->udp_checksum = 0;

    // FILL IP HEADER
    struct ipheader *ip = (struct ipheader *)buffer;
    ip->ip_ver = 4;
    ip->ip_ihl = 5;
    ip->ip_ttl = 20;
    ip->source_ip.s_addr = inet_addr("127.0.0.1");
    ip->dest_ip.s_addr = inet_addr("8.8.8.8");
    ip->ip_protocol = IPPROTO_ICMP;
    ip->ip_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));


    // FILL UDP
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader);
    const char *msg = "Hello Server!\n";
    //int data_len = strlen(msg);
    //strncpy(data, msg, data_len);
    udp->udp_srcport = htons(12345);
    udp->udp_destport = htons(9090);
    //udp->udp_len = htons(sizeof(struct udpheader) + data_len);
    udp->udp_len = htons(sizeof(struct udpheader) + sizeof(struct ipheader));
    udp->udp_checksum = 0;

    /// @brief ///
    ip->ip_protocol = IPPROTO_UDP;
    //ip->ip_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader) + data_len);
    ip->ip_len = 200;

    // send the packet
    packet_spoof(ip);
    return 0;
}
