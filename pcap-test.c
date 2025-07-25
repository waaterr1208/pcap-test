#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

struct Eth {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

struct IP {
    uint8_t version_ihl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
};

struct TCP {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

struct Payload {
    const u_char* data;
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac_addr(uint8_t* ptr) {
    printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
        ptr[0], ptr[1], ptr[2],
        ptr[3], ptr[4], ptr[5]);
}

int main(int argc, char* argv[]) {
    if(!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf); 
    if(pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null = %s\n", param.dev_, errbuf);
        return -1;
    }

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);

        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        struct Eth *eth = (struct Eth*)packet;

        struct IP *ip = (struct IP*)(packet + sizeof(struct Eth));
        uint8_t ip_hlen = (ip->version_ihl & 0x0f) * 4;
        
        if(ip->protocol != 0x06)
            continue;

        struct TCP *tcp = (struct TCP*)(packet + sizeof(struct Eth) + ip_hlen);
        uint8_t tcp_len = ((tcp->data_offset_reserved & 0xF0) >> 4) * 4;
        printf("%u\n", tcp_len);

        struct Payload payload;
        payload.data = packet + sizeof(struct Eth) + ip_hlen + tcp_len;
        
        print_mac_addr(eth->dst_mac);
        print_mac_addr(eth->src_mac);

        printf("src ip: %u.%u.%u.%u\n",
            ip->src_ip[0], ip->src_ip[1], ip->src_ip[2], ip->src_ip[3]);
        printf("dst ip: %u.%u.%u.%u\n",
            ip->dst_ip[0], ip->dst_ip[1], ip->dst_ip[2], ip->dst_ip[3]);

        printf("src port: %u\n", tcp->src_port);
        printf("dst port: %u\n", tcp->dst_port);

        uint8_t payload_len = ntohs(ip->total_length) - ip_hlen - tcp_len;
        printf("patload len: %u\n", payload_len);

        for(int i = 0; i < 20 && i < payload_len ; i++) {
            printf("%02x", payload.data[i]);
        }
        printf("\n\n");   
    }
    pcap_close(pcap);
}