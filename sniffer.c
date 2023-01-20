#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <pcap.h>

FILE *file;
int count = 0;
struct newStruct
{
    uint32_t unixtime;
    uint16_t length;
    uint16_t reserved : 3, c_flag : 1, s_flag : 1, t_flag : 1, status : 10;
    uint16_t cache;
    uint16_t padding;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *device = "lo";
    char *filter = "tcp";
    struct bpf_program filter_exp;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    count = 0;
    file = fopen("209133826_318664190.txt", "w");

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "pcan open live error %s\n", errbuf);
        return -1;
    }

    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf);
        net = 0;
        mask = 0;
    }

    if (pcap_compile(handle, &filter_exp, filter, 0, net) == -1)
    {
        fprintf(stderr, "error compiling: %s\n", errbuf);
        return -1;
    }

    if (pcap_setfilter(handle, &filter_exp) == -1)
    {
        fprintf(stderr, "error setting filter: %s\n", errbuf);
        return -1;
    }

    pcap_loop(handle, -1, got_packet, NULL);
    fclose(file);
    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethdr *ether_header;
    ether_header = (struct ethdr *)packet;
    struct ip *ip;
    struct tcphdr *tcpq;
    ip = (struct ip *)(packet + sizeof(struct ether_header));
    tcpq = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    struct newStruct *all;
    all = (struct newStruct *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
    int len_of_naor = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + sizeof(struct newStruct);
    count++;
    if (file == NULL)
    {
        printf("Error file\n");
        return;
    }

    fprintf(file, "**********************************************************\n");
    fprintf(file, "----------------------------------------------------------\n");
    fprintf(file, "--------------------Packet-Header-------------------------\n");
    fprintf(file, "Packet Number: %d \n", count);
    fprintf(file, "Source ip address: %s \n", inet_ntoa(ip->ip_src));
    fprintf(file, "Destination ip address: %s \n", inet_ntoa(ip->ip_dst));
    fprintf(file, "Source Port: %u\n", ntohs(tcpq->th_sport));
    fprintf(file, "Destination Port: %u\n", ntohs(tcpq->th_dport));
    fprintf(file, "Timestamp: %u\n", all->unixtime);
    fprintf(file, "Total length: %u \n", all->length);
    fprintf(file, "Cache flag:  %u\n", all->c_flag);
    fprintf(file, "Steps flag: %u\n", all->s_flag);
    fprintf(file, "Type_flag: %u\n", all->t_flag);
    fprintf(file, "Status code: %u\n", all->status);
    fprintf(file, "Cache control: %u\n", all->cache);
    fprintf(file, "------------------------PAYLOAD---------------------------\n");
    for (int i = 0; i < len_of_naor; i++)
    {
        if (!(i & 15))
            fprintf(file, "\n%04X:  ", i);
        fprintf(file, "%02X ", ((unsigned char *)packet)[i]);
    }
    fprintf(file, "\n");
    fprintf(file, "----------------------------------------------------------\n");
    fprintf(file, "**********************************************************\n");
    fprintf(file, "\n");
    fprintf(file, "\n");
}
