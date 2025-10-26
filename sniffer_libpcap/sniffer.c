#include <stdio.h>
#include <stdlib.h>
#include <string.h>         
#include <ctype.h>          
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <pcap/pcap.h>
#include <arpa/inet.h> 
#include <netinet/tcp.h>
#include <netinet/udp.h>    
#include <time.h>          
#include <signal.h>         

// questa serve a gestire una sola connessione
struct tcp_connection {
    struct in_addr ip_src;
    struct in_addr ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
    
    long packet_count;
    long byte_count;
    time_t start_time;
    
    // per creare la lista
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



// variabile globale per l'handle pcap
static pcap_t *t_handle_global;

void stop_capture(int signum) {
    (void)signum; // silenzia il warning
    printf("\nInterruzione... (Premi di nuovo Ctrl+C per forzare)\n");
    if (t_handle_global) {
        pcap_breakloop(t_handle_global);
    }
}



// funzione helper per trovare una connessione 
struct tcp_connection* find_connection(struct global_state *state, struct ip *ip_h, struct tcphdr *tcp_h) {
    struct tcp_connection *conn = state->connection_list_head;
    uint16_t src_port = ntohs(tcp_h->th_sport);
    uint16_t dst_port = ntohs(tcp_h->th_dport);

    while (conn != NULL) {
        // controlla in entrambe le direzioni
        if (conn->ip_src.s_addr == ip_h->ip_src.s_addr && 
            conn->ip_dst.s_addr == ip_h->ip_dst.s_addr &&
            conn->port_src == src_port &&
            conn->port_dst == dst_port) {
            return conn;
        }
        if (conn->ip_src.s_addr == ip_h->ip_dst.s_addr && 
            conn->ip_dst.s_addr == ip_h->ip_src.s_addr &&
            conn->port_src == dst_port &&
            conn->port_dst == src_port) {
            return conn;
        }
        conn = conn->next;
    }
    return NULL; 
}


//funzione di callback
void print_packet_info(u_char *user, const struct pcap_pkthdr *pkthdr, 
                       const u_char *packet) {
    
    
    struct global_state *state = (struct global_state *)user;

    printf("----------------------------------------\n");
    
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    


    const int ethernet_header_length = 14;
    
    struct ip *ip_h = (struct ip *)(packet + ethernet_header_length);
    int ip_header_length = ip_h->ip_hl * 4;

    // printf("  IP Header Length: %d byte\n", ip_header_length); 


    // --- PARSING TCP ---
    if (ip_h->ip_p == IPPROTO_TCP) {
        printf("  Protocollo: TCP\n");
        struct tcphdr *tcp_h = (struct tcphdr *)(packet + ethernet_header_length + ip_header_length);
        int tcp_header_length = tcp_h->th_off * 4;
        int payload_length = pkthdr->len - (ethernet_header_length + ip_header_length + tcp_header_length);
        
        int src_port = ntohs(tcp_h->th_sport);
        int dst_port = ntohs(tcp_h->th_dport);

        printf("  Porte: %d -> %d\n", src_port, dst_port);

        
        if (src_port == 80 || dst_port == 80) {
            state->http_requests++;
            printf("    [!] Pacchetto HTTP rilevato!\n");
        }
        
        struct tcp_connection *conn = find_connection(state, ip_h, tcp_h);

        
        if (tcp_h->th_flags & TH_SYN) {
            if (conn == NULL) { // solo se è una NUOVA connessione
                printf("    [+] Nuova connessione TCP tracciata.\n");
                // alloca memoria per la nuova connessione
                struct tcp_connection *new_conn = (struct tcp_connection*)malloc(sizeof(struct tcp_connection));
                if (new_conn == NULL) {
                    fprintf(stderr, "Errore: malloc fallita!\n");
                    return;
                }
                
               
                new_conn->ip_src = ip_h->ip_src; 
                new_conn->ip_dst = ip_h->ip_dst;
                new_conn->port_src = src_port;
                new_conn->port_dst = dst_port;
                new_conn->packet_count = 1;
                new_conn->byte_count = pkthdr->len;
                new_conn->start_time = time(NULL);

                //  si aggiunge in testa alla lista
                new_conn->next = state->connection_list_head;
                state->connection_list_head = new_conn;
                state->active_tcp_connections++;
            }
        } else if (tcp_h->th_flags & (TH_FIN | TH_RST)) {
             if (conn != NULL) {
                printf("    [-] Connessione TCP chiusa.\n");
                
                state->active_tcp_connections--; // semplice decremento
             }
        } else if (conn != NULL) {
            // aggiorna una connessione esistente
            conn->packet_count++;
            conn->byte_count += pkthdr->len;
        }

        if (payload_length > 0 && (src_port == 80 || dst_port == 80)) {
            printf("  Payload HTTP (%d byte):\n", payload_length);
            
        }
    }
    //udp
    else if (ip_h->ip_p == IPPROTO_UDP) {
        printf("  Protocollo: UDP\n");
        struct udphdr *udp_h = (struct udphdr *)(packet + ethernet_header_length + ip_header_length);
        int src_port = ntohs(udp_h->uh_sport);
        int dst_port = ntohs(udp_h->uh_dport);
        
        printf("  Porte: %d -> %d\n", src_port, dst_port);
        
        if (src_port == 53 || dst_port == 53) {
            state->dns_queries++;
            printf("    [!] Pacchetto DNS rilevato!\n");
        }
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
    
    char filter_exp[] = "(tcp and port 80) or (udp and port 53) or (tcp and port 443) ";
    printf("Device: %s\n", dev);

    pcap_t *t_handle;
    
    t_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (t_handle == NULL) {
        printf("Err: pcap_open_live() %s\n", errbuf);
        exit(1);
    }
    
    
    t_handle_global = t_handle;
    signal(SIGINT, stop_capture); 

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
        fprintf(stderr, "ERR: pcap_loop() failed!\n"); 
    }

    printf("\n--- Cattura Terminata ---\n");
    
    
    printf("Riepilogo:\n");
    printf("  Richieste HTTP (porta 80): %ld\n", my_sniffer_state.http_requests);
    printf("  Query DNS (porta 53):    %ld\n", my_sniffer_state.dns_queries);
    printf("  Connessioni TCP attive:  %d\n", my_sniffer_state.active_tcp_connections);
    
    // qui dovrei fare free su ogni connessione

    pcap_freecode(&fp);
    pcap_close(t_handle);
    
    return 0;
}