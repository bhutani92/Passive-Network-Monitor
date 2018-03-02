#include <main.h>

void finalize(char *interface, char *file, char *str, char *expr) {
    IF_FREE(interface);
    IF_FREE(file);
    IF_FREE(str);
    IF_FREE(expr);
}

uint16_t checkEthernetType(struct ether_header *ether) {
    uint16_t ether_type = ntohs(ether->ether_type);
    switch(ether_type) {
        case ETHERTYPE_IP :
            return ETHERTYPE_IP;
        case ETHERTYPE_ARP :
            return ETHERTYPE_ARP;
        case ETHERTYPE_REVARP :
            return ETHERTYPE_REVARP;
        case ETHERTYPE_IPV6 :
            return ETHERTYPE_IPV6;
        default :
            return 0x00;
    }
}

void printPayload(u_char *payload, int pkt_len) {
    if (!pkt_len) {
        return;
    }

    cout << endl;
    char printable_char[20];
    int i = 0;
    while(pkt_len > 0) {
        unsigned char c1 = *payload;
        unsigned char c2 = *(payload + 1);
        
        printf("%2.2x%2.2x ", c1, c2);
        if (isprint(c1)) {
            if (c1 == ' ') {
                printable_char[i] = '.';
            } else {
                printable_char[i] = c1;
            }
            i++;
        } else {
            printable_char[i] = '.';
            i++;
        }

        if (isprint(c2)) {
            if (c2 == ' ') {
                printable_char[i] = '.';
            } else {
                printable_char[i] = c2;
            }
            i++;
        } else {
            printable_char[i] = '.';
            i++;
        }

        payload += 2;
        if (i == 16) {
            printable_char[i] = '\0';
            cout << printable_char << endl;
            memset(printable_char, 0, sizeof(printable_char));
            i = 0;
        }
        pkt_len -= 2;
    }

    while (i % 16 != 0) {
        cout << "  "; 
        i++;
        if (i % 2 == 0) {
            cout << " ";
        }
    }
    printable_char[i] = '\0';
    cout << printable_char << endl;
   
    printf("\n");
}

u_char *strstr(u_char *haystack, char *needle, int pkt_len) {
    int count = 0;
    int len = strlen(needle);
    if (needle == NULL) {
        return haystack; 
    }

    while(pkt_len--) {
        char c = *haystack;
        if (c != *needle) {
            count = 0;
            haystack++;
            continue;
        }
        count++;
        if (count == len) {
            return (haystack - len + 1);
        }
        needle++;
        haystack++;
    }
    return NULL;
}

char *convertMACAddressFormat(char *mac) {
    char *convertedMac = (char *)malloc(MAC_ADDRESS_LENGTH * sizeof(char));
    convertedMac[0] = '\0';
    char *token = NULL;
    
    token = strtok(mac, ":\n");
    while(token != NULL) {
        if (convertedMac[0] == '\0') {
            if (strlen(token) == 2) {
                strcpy(convertedMac, token);
            } else {
                strcpy(convertedMac, "0");
                strcat(convertedMac, token);
            }
        } else {
            if (strlen(token) == 2) {
                strcat(convertedMac, ":");
                strcat(convertedMac, token);
            } else {
                strcat(convertedMac, ":0");
                strcat(convertedMac, token);
            }
        }
        token = strtok(NULL, ":\n");
    }

    return convertedMac;
}

portInfo *parseTCP(char *str, const struct pcap_pkthdr *header, const u_char *pkt) {
    sniff_tcp *tcp = (sniff_tcp *)(pkt + sizeof(struct ether_header) + sizeof(sniff_ip));
    unsigned int tcp_len = header->len - sizeof(struct ether_header) - sizeof(sniff_ip);
    portInfo *port = (portInfo *)malloc(sizeof(portInfo));

    if (tcp_len < sizeof(sniff_tcp)) {
        cout << "Invalid TCP Packet. Discarding the packet :" << tcp_len << endl;
        port->srcPort = 0;
        port->destPort = 0;
        return port;
    }

    port->srcPort = ntohs(tcp->th_sport);
    port->destPort = ntohs(tcp->th_dport);

    return port;
}

portInfo *parseUDP(char *str, const struct pcap_pkthdr *header, const u_char *pkt) {
    struct udphdr *udp = (struct udphdr *)(pkt + sizeof(struct ether_header) + sizeof(sniff_ip));
    unsigned int udp_len = header->len - sizeof(struct ether_header) - sizeof(sniff_ip);
    portInfo *port = (portInfo *)malloc(sizeof(portInfo));

    if (udp_len < sizeof(struct udphdr)) {
        cout << "Invalid UDP Packet. Discarding the packet :" << udp_len << endl;
        port->srcPort = 0;
        port->destPort = 0;
        return port;
    }

    port->srcPort = ntohs(udp->uh_sport);
    port->destPort = ntohs(udp->uh_dport);

    return port;
}

portInfo *parseICMP(char *str, const struct pcap_pkthdr *header, const u_char *pkt) {
    portInfo *port = (portInfo *)malloc(sizeof(portInfo));
    port->srcPort = 0;
    port->destPort = 0; 

    return port;
}

portInfo *parseOthers(char *str, const struct pcap_pkthdr *header, const u_char *pkt) {
    portInfo *port = (portInfo *)malloc(sizeof(portInfo));
    port->srcPort = 0;
    port->destPort = 0; 

    return port;
}

void analyze_IPpacket(char *str, const struct pcap_pkthdr *header, const u_char *pkt, uint16_t ether_type) {
    char *srcMAC, *destMAC;
    struct ether_header *ether = (struct ether_header *)pkt;
    sniff_ip *ip = (sniff_ip *)(pkt + sizeof(struct ether_header));
    unsigned int ip_len = header->len - sizeof(struct ether_header);

    if (ip_len < sizeof(sniff_ip)) {
        cout << "Invalid IP Packet. Discarding the packet" << endl;
        return;
    }

    char srcIP[IP_ADDRESS_LENGTH], destIP[IP_ADDRESS_LENGTH];
    strcpy(srcIP, inet_ntoa(ip->ip_src));
    strcpy(destIP, inet_ntoa(ip->ip_dst));
    portInfo *port;

    struct tm *pkt_time = localtime((const time_t *)&header->ts.tv_sec);
    char time_buf[TIME_BUFFER_LENGTH];
    strftime(time_buf, TIME_BUFFER_LENGTH, "%Y-%m-%d %H:%M:%S", pkt_time);
    
    uint64_t time_ms = (header->ts.tv_usec);

    srcMAC = convertMACAddressFormat(ether_ntoa((struct ether_addr *)&ether->ether_shost));
    destMAC = convertMACAddressFormat( ether_ntoa((struct ether_addr *)&ether->ether_dhost));
    
    u_char * payload = (u_char *)(pkt + sizeof(struct ether_header));
    int payload_len = ip_len;

    ip_len -= sizeof(sniff_ip);

    if (ip->ip_p == IPPROTO_TCP) {
        port = parseTCP(str, header, pkt);
        if (str != NULL && !strstr(payload, str, payload_len)) {
            return;
        }
        printf("%s.%lu %s -> %s type 0x%3X ", time_buf, time_ms, srcMAC, destMAC, ether_type);
        printf("len %d %s:%d -> %s:%d TCP", header->len, srcIP, port->srcPort, destIP, port->destPort);
    } else if (ip->ip_p == IPPROTO_UDP) {
        port = parseUDP(str, header, pkt);
        if (str != NULL && !strstr(payload, str, payload_len)) {
            return;
        }
        ip_len -= sizeof(struct udphdr);
        printf("%s.%lu %s -> %s type 0x%3X ", time_buf, time_ms, srcMAC, destMAC, ether_type);
        printf("len %d %s:%d -> %s:%d UDP", ip_len, srcIP, port->srcPort, destIP, port->destPort);    
    } else if (ip->ip_p == IPPROTO_ICMP) {
        port = parseICMP(str, header, pkt);
        if (str != NULL && !strstr(payload, str, payload_len)) {
            return;
        }
        printf("%s.%lu %s -> %s type 0x%3X ", time_buf, time_ms, srcMAC, destMAC, ether_type);
        printf("len %d %s -> %s: ICMP", header->len, srcIP, destIP);    
    } else {
        port = parseOthers(str, header, pkt);
        if (str != NULL && !strstr(payload, str, payload_len)) {
            return;
        }
        printf("%s.%lu %s -> %s type 0x%3X ", time_buf, time_ms, srcMAC, destMAC, ether_type);
        printf("len %d %s -> %s: OTHER", header->len, srcIP, destIP);    
    }

    printPayload(payload, payload_len);
}

void analyze_ARPpacket(char *str, const struct pcap_pkthdr *header, const u_char *pkt, uint16_t ether_type) {
    struct ether_header *ether = (struct ether_header *)pkt;
    unsigned int arp_len = header->len - sizeof(struct ether_header);

    if (arp_len < sizeof(struct arphdr)) {
        cout << "Invalid ARP Packet. Discarding the packet" << endl;
        return;
    }

    u_char *payload = (u_char *)(pkt + sizeof(struct ether_header));
    
    if (str != NULL && !strstr(payload, str, arp_len)) {
        return;
    }
    
    char *srcMAC, *destMAC;
    struct tm *pkt_time = localtime((const time_t *)&header->ts.tv_sec);
    char time_buf[TIME_BUFFER_LENGTH];
    strftime(time_buf, TIME_BUFFER_LENGTH, "%Y-%m-%d %H:%M:%S", pkt_time);
    
    uint64_t time_ms = (header->ts.tv_usec);

    srcMAC = convertMACAddressFormat(ether_ntoa((struct ether_addr *)&ether->ether_shost));
    destMAC = convertMACAddressFormat( ether_ntoa((struct ether_addr *)&ether->ether_dhost));

    printf("%s.%lu %s -> %s type 0x%3X ", time_buf, time_ms, srcMAC, destMAC, ether_type);
    printf("len %d", arp_len);

    printPayload(payload, arp_len);
}

void analyze_RARPpacket(char *str, const struct pcap_pkthdr *header, const u_char *pkt, uint16_t ether_type) {
    struct ether_header *ether = (struct ether_header *)pkt;
    unsigned int rarp_len = header->len - sizeof(struct ether_header);
    
    if (rarp_len < sizeof(struct arphdr)) {
        cout << "Invalid RARP Packet. Discarding the packet" << endl;
        return;
    }

    u_char *payload = (u_char *)(pkt + sizeof(struct ether_header));
    
    if (str != NULL && !strstr(payload, str, rarp_len)) {
        return;
    }
    
    char *srcMAC, *destMAC;
    struct tm *pkt_time = localtime((const time_t *)&header->ts.tv_sec);
    char time_buf[TIME_BUFFER_LENGTH];
    strftime(time_buf, TIME_BUFFER_LENGTH, "%Y-%m-%d %H:%M:%S", pkt_time);
    
    uint64_t time_ms = (header->ts.tv_usec);

    srcMAC = convertMACAddressFormat(ether_ntoa((struct ether_addr *)&ether->ether_shost));
    destMAC = convertMACAddressFormat( ether_ntoa((struct ether_addr *)&ether->ether_dhost));

    printf("%s.%lu %s -> %s type 0x%3X ", time_buf, time_ms, srcMAC, destMAC, ether_type);
    printf("len %d", rarp_len);

    printPayload(payload, rarp_len);
}

void analyze_IPV6packet(char *str, const struct pcap_pkthdr *header, const u_char *pkt, uint16_t ether_type) {
    struct ether_header *ether = (struct ether_header *)pkt;
    unsigned int ip6_len = header->len - sizeof(struct ether_header);
   
    if (ip6_len < sizeof(struct ip6_hdr)) {
        cout << "Invalid IPV6 Packet. Discarding the packet" << endl;
        return;
    }

    u_char *payload = (u_char *)(pkt + sizeof(struct ether_header));
    //u_char *payload = (u_char *)(pkt + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct ip6_ext));
    //uint64_t payload_len = header->len - sizeof(struct ether_header) + sizeof(struct ip6_hdr) + ext_hdr_len * sizeof(struct ip6_ext);
    int payload_len = ip6_len;
    
    if (str != NULL && !strstr(payload, str, payload_len)) {
        return;
    }
    
    char *srcMAC, *destMAC;
    struct tm *pkt_time = localtime((const time_t *)&header->ts.tv_sec);
    char time_buf[TIME_BUFFER_LENGTH];
    strftime(time_buf, TIME_BUFFER_LENGTH, "%Y-%m-%d %H:%M:%S", pkt_time);
    
    uint64_t time_ms = (header->ts.tv_usec);

    srcMAC = convertMACAddressFormat(ether_ntoa((struct ether_addr *)&ether->ether_shost));
    destMAC = convertMACAddressFormat( ether_ntoa((struct ether_addr *)&ether->ether_dhost));

    printf("%s.%lu %s -> %s type 0x%3X ", time_buf, time_ms, srcMAC, destMAC, ether_type);
    printf("len %d", header->len);

    printPayload(payload, payload_len);
}

void analyze_packet(u_char *str, const struct pcap_pkthdr *header, const u_char *pkt) {
    uint16_t ether_type;
    struct ether_header *ether = (struct ether_header *)pkt;

    ether_type = checkEthernetType(ether);

    if (ether_type == ETHERTYPE_IP) {
        analyze_IPpacket((char *)str, header, pkt, ether_type);
    } else if (ether_type == ETHERTYPE_ARP) {
        analyze_ARPpacket((char *)str, header, pkt, ether_type);
    } else if (ether_type == ETHERTYPE_REVARP) {
        analyze_RARPpacket((char *)str, header, pkt, ether_type);
    } else if (ether_type == ETHERTYPE_IPV6) {
        analyze_IPV6packet((char *)str, header, pkt, ether_type);
    } else if (ether_type == 0x00) {
        // Handle other cases
        return;
    }
}

void processPcapPackets(char *interface, char *file, char *str, char *expr) {
    char err_buf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    bpf_u_int32 mask = 0;
    bpf_u_int32 net = 0;
    struct bpf_program filter;
    //struct pcap_pkthdr header;

    if (!interface) {
        interface = pcap_lookupdev(err_buf);
        if (!interface) {
            cout << "Unable to find default device. Returning." << endl;
            return;
        }
    }

    if (pcap_lookupnet(interface, &net, &mask, err_buf) == -1) {
        cout << "Unable to determine IPV4 network number and netmask for interface \"" << interface << "\". Setting both to 0." << endl;
        net = 0;
        mask = 0;
    }

    if (!file) {
        handle = pcap_open_live(interface, BUFSIZ, 1, -1, err_buf);
        if (handle == NULL) {
            cout << "Cannot sniff on interface " << interface << endl;
            return;
        }
    } else {
        handle = pcap_open_offline(file, err_buf);
        if (handle == NULL) {
            cout << "Cannot read from the file " << file << endl;
            return;
        }
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        cout << "No ethernet headers supported" << endl;
        return;
    }

    if (expr) {
        if (pcap_compile(handle, &filter, expr, 0, net) == -1) {
            cout << "Cannot parse filter " << expr << ". Error Message " << pcap_geterr(handle) << endl;
            return;
        }

        if (pcap_setfilter(handle, &filter) == -1) {
            cout << "Cannot set filter " << expr << ". Error Message " << pcap_geterr(handle) << endl;
            return;
        }
    }

    /*const u_char *text = pcap_next(handle, &header);
    cout << "Header length :" << header.len << endl;
    cout<<"Text : "<<text<<endl;
    cout << "Timestamp :"<<header.ts.tv_sec;  */
    if (pcap_loop(handle, -1, analyze_packet, (u_char *)str) < 0) {
        cout << "Exiting PCAP Loop" << endl;
        return;
    }
    pcap_close(handle);
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    char *file = NULL;
    char *str = NULL;
    char *expr = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "-i", OPTIONS_LENGTH)) {
            if (argv[i + 1] && !strncmp(argv[i + 1], "-", OPTIONS_LENGTH - 1) && (strlen(argv[i + 1]) == OPTIONS_LENGTH)) {
                cout << "Unidentified format\n";
                cout << "Format is : mydump [-i interface] [-r file] [-s string] [\"expression\"]\n";
                return 0;
            }
            interface = strdup(argv[i + 1]);
            i++;
        } else if (!strncmp(argv[i], "-r", OPTIONS_LENGTH)) {
            if (argv[i + 1] && !strncmp(argv[i + 1], "-", OPTIONS_LENGTH - 1) && (strlen(argv[i + 1]) == OPTIONS_LENGTH)) {
                cout << "Unidentified format\n";
                cout << "Format is : mydump [-i interface] [-r file] [-s string] [\"expression\"]\n";
                return 0;
            }
            file = strdup(argv[i + 1]);
            i++;
        } else if (!strncmp(argv[i], "-s", OPTIONS_LENGTH)) {
            if (argv[i + 1] && !strncmp(argv[i + 1], "-", OPTIONS_LENGTH - 1) && (strlen(argv[i + 1]) == OPTIONS_LENGTH)) {
                cout << "Unidentified format\n";
                cout << "Format is : mydump [-i interface] [-r file] [-s string] [\"expression\"]\n";
                return 0;
            }
            str = strdup(argv[i + 1]);
            i++;
        } else if (!strncmp(argv[i], "-", OPTIONS_LENGTH - 1) && (strlen(argv[i]) == OPTIONS_LENGTH)) {
            //Invalid Option Specified
            cout << "Invalid Option. Returning." << endl;
            finalize(interface, file, str, expr);
            return 0;
        } else {
            expr = strdup(argv[i]);
        }
    }

    if (interface != NULL && file != NULL) {
        cout << "Ignoring interface " << interface << " as file " << file << " is specified!!" << endl;
    }
    processPcapPackets(interface, file, str, expr);

    finalize(interface, file, str, expr);
    return 0;
}
