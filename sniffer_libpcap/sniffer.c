#include <stdio.h>
#include <stdlib.h>
#include <string.h>         
#include <ctype.h>          
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <pcap/pcap.h>
#include <arpa/inet.h> 
#include <netinet/tcp.h>


// questa serve a gestire una sola connessione
struct tcp_connection {
    struct in_addr ip_src;
    struct in_addr ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
    
    // "e altro?"
    long packet_count;
    long byte_count;
    time_t start_time;
    
    // Per creare la lista
    struct tcp_connection *next;
};

// questa serve a gestire tutte le connessioni
struct global_state {
    
    // lista di connessioni alla struct tcp
    struct tcp_connection *connection_list_head; // la testa della tua linked list
    int active_tcp_connections;                 

   
    long dns_queries;   // contatore per i pacchetti UDP 
    long http_requests; // contatore per i pacchetti TCP 
};




//funzione di callback
void print_packet_info(u_char *user, const struct pcap_pkthdr *pkthdr, 
                       const u_char *packet) {
    
    struct global_state *state = (struct global_state *)user;

    printf("----------------------------------------\n");
    
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Pacchetto non-IP ricevuto (probabilmente ARP o IPv6). Skipping...\n");
        return;
    }

    printf("Pacchetto IP (IPv4) ricevuto!\n");

    const int ethernet_header_length = 14;

    
    struct ip *ip_h = (struct ip *)(packet + ethernet_header_length);
    int ip_header_length = ip_h->ip_hl * 4;

    printf("  IP Header Length: %d byte\n", ip_header_length);

    //  Creiamo un buffer locale per la sorgente
    char src_ip_buffer[INET_ADDRSTRLEN];
    
    // Convertiamo l'IP sorgente e lo copiamo nel nostro buffer
    strcpy(src_ip_buffer, inet_ntoa(ip_h->ip_src));
    
    // Ora possiamo convertire la destinazione 
    char *dst_ip_str = inet_ntoa(ip_h->ip_dst);

    printf("  Sorgente: %s\n", src_ip_buffer);
    printf("  Destinazione: %s\n", dst_ip_str);
    


    // --- PARSING TCP ---
    if (ip_h->ip_p != IPPROTO_TCP) {
        printf("  Protocollo: Non-TCP. Skipping...\n");
        return;
    }
    
    printf("  Protocollo: TCP\n");
    
    // Trova l'inizio dell'header TCP
    struct tcphdr *tcp_h = (struct tcphdr *)(packet + ethernet_header_length + ip_header_length);
    
    // Leggi le porte
    int src_port = ntohs(tcp_h->th_sport);
    int dst_port = ntohs(tcp_h->th_dport);

    printf("  Porta Sorgente: %d\n", src_port);
    printf("  Porta Destinazione: %d\n", dst_port);

    // Analizza i Flag!
    printf("  Flags:\n");
    if (tcp_h->th_flags & TH_SYN) printf("    [SYN] (Inizio connessione)\n");
    if (tcp_h->th_flags & TH_ACK) printf("    [ACK] (Conferma)\n");
    if (tcp_h->th_flags & TH_FIN) printf("    [FIN] (Chiusura connessione)\n");
    if (tcp_h->th_flags & TH_RST) printf("    [RST] (Reset connessione)\n");
    if (tcp_h->th_flags & TH_PUSH) printf("    [PSH] (Push dati)\n");
    
    // Analizza il Payload (i dati veri e propri)
    int tcp_header_length = tcp_h->th_off * 4;
    int payload_length = pkthdr->len - (ethernet_header_length + ip_header_length + tcp_header_length);
    
    if (payload_length > 0) {
        printf("  Payload (%d byte):\n", payload_length);
        
        const u_char *payload = (packet + ethernet_header_length + ip_header_length + tcp_header_length);
        
        
        int len_to_print = (payload_length < 50) ? payload_length : 50;
        
        for(int i = 0; i < len_to_print; i++) {
            if (isprint(payload[i])) {
                printf("%c", payload[i]);
            } else {
                printf("."); // un . per i byte non stampabili
            }
        }
        printf("\n");
    }
}







int main(void) {
    char *dev = "en0";
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    struct global_state my_sniffer_state;
    my_sniffer_state.connection_list_head = NULL;
    my_sniffer_state.active_tcp_connections = 0;
    my_sniffer_state.dns_queries = 0;
    my_sniffer_state.http_requests = 0;
    char filter_exp[] = "(tcp and port 80) or (udp and port 53)";
    printf("Device: %s\n", dev);

    pcap_t *t_handle;
    
    t_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (t_handle == NULL) {
        printf("Err: pcap_open_live() %s\n", errbuf);
        exit(1);
    }

    if (pcap_compile(t_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Errore pcap_compile: %s\n", pcap_geterr(t_handle));
        exit(1);
    }

    if (pcap_setfilter(t_handle, &fp) == -1) {
        fprintf(stderr, "Errore pcap_setfilter: %s\n", pcap_geterr(t_handle));
        exit(1);
    }

    printf("Filtro '%s' applicato. In attesa di pacchetti... (Premi Ctrl+C per fermare)\n", filter_exp);

    int packet_to_sniff = -1; // Loop infinito

    if (pcap_loop(t_handle, packet_to_sniff, print_packet_info, (u_char*)&my_sniffer_state) == -1) {
        fprintf(stderr, "ERR: pcap_loop() failed: %s\n", pcap_geterr(t_handle));
    }

    printf("\nCattura terminata.\n");
    
    pcap_freecode(&fp);
    pcap_close(t_handle);
    
    return 0;
}