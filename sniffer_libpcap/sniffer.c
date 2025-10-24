#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <pcap/pcap.h>
#include <arpa/inet.h> 


//funzione di callback
void print_packet_info(u_char *user, const struct pcap_pkthdr *pkthdr, 
                       const u_char *packet) {
    
    (void)user;
    (void)pkthdr; 

    printf("----------------------------------------\n");
    
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    
    // Questo controllo ora è ridondante ora che ho messo il filtro BPF,
    // ma è buona norma tenerlo.
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Pacchetto non-IP ricevuto (probabilmente ARP o IPv6). Skipping...\n");
        return;
    }

    printf("Pacchetto IP (IPv4) ricevuto!\n");

    const int ethernet_header_length = 14;

    // --- PARSING IP CORRETTO ---

    // cast al tipo corretto (struct ip)
    struct ip *ip_h = (struct ip *)(packet + ethernet_header_length);

    // calcola la lunghezza dell'header IP
    // ip_hl è "header length" in parole da 4 byte, quindi moltiplica * 4
    int ip_header_length = ip_h->ip_hl * 4;

    printf("  IP Header Length: %d byte\n", ip_header_length);

    // converti gli IP binari in stringhe
    // inet_ntoa (da <arpa/inet.h>) converte ip_src e ip_dst
    char *src_ip_str = inet_ntoa(ip_h->ip_src);
    char *dst_ip_str = inet_ntoa(ip_h->ip_dst);

    printf("  Sorgente: %s\n", src_ip_str);
    printf("  Destinazione: %s\n", dst_ip_str);


    // --- PARSING TCP ---
    if (ip_h->ip_p != IPPROTO_TCP) {
        printf("  Protocollo: Non-TCP. Skipping...\n");
        return;
    }
    
    printf("  Protocollo: TCP\n");
    
}


int main(void) {
    char *dev = "en0";
    char errbuf[PCAP_ERRBUF_SIZE];
    // filtro per prendere solo pacchetti che ci interessano
    struct bpf_program fp;
    //filtriamo per prendere solo ip packet
    char filter_exp[] = "ip and tcp";
    bpf_u_int32 net;
    printf("Device: %s\n", dev);

    pcap_t *t_handle;
    
    t_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (t_handle == NULL) {
        printf("Err: pcap_open_live() %s\n", errbuf);
        exit(1);
    }

    // compila il filtro
    if (pcap_compile(t_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Errore pcap_compile: %s\n", pcap_geterr(t_handle));
        exit(1);
    }

    //  applica il filtro alla sessione
    if (pcap_setfilter(t_handle, &fp) == -1) {
        fprintf(stderr, "Errore pcap_setfilter: %s\n", pcap_geterr(t_handle));
        exit(1);
    }

    printf("Filtro '%s' applicato. In attesa di pacchetti...\n", filter_exp);

    int packet_to_sniff = -1;


    if (pcap_loop(t_handle, packet_to_sniff, print_packet_info, (u_char*)NULL) == -1) {
        // Gestione errore migliorata
        fprintf(stderr, "ERR: pcap_loop() failed: %s\n", pcap_geterr(t_handle));
        exit(1);
    }

    pcap_freecode(&fp);
    //chiudere handle
    pcap_close(t_handle);
    
    return 0;
}