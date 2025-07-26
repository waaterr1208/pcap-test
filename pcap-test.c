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

typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} Eth;

typedef struct {
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
} Ip;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} Tcp;

typedef struct {
    const u_char* data;
} Payload;

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac_addr(uint8_t* ptr) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
        ptr[0], ptr[1], ptr[2],
        ptr[3], ptr[4], ptr[5]);
}

void print_ip_addr(uint8_t* ptr){
    printf("%u.%u.%u.%u",
    ptr[0], ptr[1], ptr[2], ptr[3]);
}

void print_payload(uint8_t len, Payload* payload){
    uint8_t max = (len < 20) ? len : 20;
    for(int i = 0; i<max ; i++) {
        printf("%02x", payload->data[i]);
        if(i != max - 1)
            printf("|");
    }   
}

void print_information(Eth* eth, Ip* ip, Tcp* tcp, Payload* payload, uint8_t payload_len){
    printf("MAC: ");
    print_mac_addr(eth->src_mac);
    printf(" -> ");
    print_mac_addr(eth->dst_mac);
    printf("\n");
    printf("IP: ");
    print_ip_addr(ip->src_ip);
    printf(" -> ");
    print_ip_addr(ip->dst_ip);
    printf("\n");
    printf("PORT: ");
    printf("%u -> ", ntohs(tcp->src_port));
    printf("%u\n", ntohs(tcp->dst_port));
    printf("PAYLOAD: ");
    print_payload(payload_len, payload);
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

        Eth *eth = (Eth*)packet;

        Ip *ip = (Ip*)(packet + sizeof(Eth));
        uint8_t ip_hlen = (ip->version_ihl & 0x0f) * 4;
        
        if(ip->protocol != 0x06) // TCP 아니면 무시
            continue;

        Tcp *tcp = (Tcp*)(packet + sizeof(Eth) + ip_hlen);
        uint8_t tcp_len = ((tcp->data_offset_reserved & 0xF0) >> 4) * 4;
        
        Payload payload;
        payload.data = packet + sizeof(Eth) + ip_hlen + tcp_len;
        uint8_t payload_len = ntohs(ip->total_length) - ip_hlen - tcp_len;

        print_information(eth, ip, tcp, &payload, payload_len);

        printf("\n\n");   
    }
    pcap_close(pcap);
}