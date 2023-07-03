#include <iostream>
#include <pcap.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct ether_header {
    uint8_t  ether_dhost[6];
    uint8_t  ether_shost[6];
    uint16_t ether_type;
};

void packetHandler(unsigned char *userData, const struct pcap_pkthdr *pkthdr, const unsigned char *packetData) {
    struct ether_header *ethHeader;
    struct ip *ipHeader;
    struct tcphdr *tcpHeader;
    struct udphdr *udpHeader;
    const char *payload;

    ethHeader = (struct ether_header *)packetData;
    ipHeader = (struct ip *)(packetData + sizeof(struct ether_header));

    if (ipHeader->ip_p == IPPROTO_TCP) {
        tcpHeader = (struct tcphdr *)(packetData + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
        payload = (const char *)(packetData + sizeof(struct ether_header) + ipHeader->ip_hl * 4 + tcpHeader->th_off * 4);

        std::cout << "TCP Packet:" << std::endl;
        std::cout << "Source IP: " << inet_ntoa(ipHeader->ip_src) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ipHeader->ip_dst) << std::endl;
        std::cout << "Source Port: " << ntohs(tcpHeader->th_sport) << std::endl;
        std::cout << "Destination Port: " << ntohs(tcpHeader->th_dport) << std::endl;
        std::cout << "Payload: " << payload << std::endl;
        std::cout << std::endl;
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        udpHeader = (struct udphdr *)(packetData + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
        payload = (const char *)(packetData + sizeof(struct ether_header) + ipHeader->ip_hl * 4 + sizeof(struct udphdr));

        std::cout << "UDP Packet:" << std::endl;
        std::cout << "Source IP: " << inet_ntoa(ipHeader->ip_src) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(ipHeader->ip_dst) << std::endl;
        std::cout << "Source Port: " << ntohs(udpHeader->uh_sport) << std::endl;
        std::cout << "Destination Port: " << ntohs(udpHeader->uh_dport) << std::endl;
        std::cout << "Payload: " << payload << std::endl;
        std::cout << std::endl;
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const unsigned char *packet;

    // Open the network device for sniffing
    handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Failed to open network device: " << errbuf << std::endl;
        return 1;
    }

    // Start capturing packets
    pcap_loop(handle, 0, packetHandler, nullptr);

    // Close the capture handle
    pcap_close(handle);

    return 0;
}
