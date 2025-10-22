#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>     // Per getpid()
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>      // Per getaddrinfo
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>  // Per inet_ntop
#include <netinet/ip.h> // Contiene la struct ip
#include <sys/time.h>   // Per gettimeofday e timeval

/* Calcola la checksum ICMP (algoritmo standard) */
static unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Utilizzo: %s <host>\n", argv[0]);
        return 1;
    }
    const char *host = argv[1];

    if (getuid() != 0)
    {
        fprintf(stderr, "%s: This program requires root privileges!\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_RAW;

    int rv = getaddrinfo(host, NULL, &hints, &res);
    if (rv != 0) {
        // Se getaddrinfo fallisce, stampa un errore comprensibile e esce
        fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(rv));
        return 1;
    }
    //prendiamo il primo ipv4
    struct sockaddr_in *dest_addr = (struct sockaddr_in*)res->ai_addr;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(dest_addr->sin_addr), ip_str, sizeof(ip_str));
    printf("PING %s (%s):\n", host, ip_str);

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0) {
        perror("socket() failed");
        freeaddrinfo(res);
        return 1;
    }

    // FONDAMENTALE. Se l'host non risponde, recvfrom()
    // aspetterà per sempre.
    struct timeval timeout;
    timeout.tv_sec = 3; // 3 secondi
    timeout.tv_usec = 0;
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt(SO_RCVTIMEO) fallito");
        close(s);
        freeaddrinfo(res);
        return 1;
    }

    //Costruzione del Pacchetto ICMP ---
    #define PACKET_SIZE 64
    char packet[PACKET_SIZE];
    struct icmp *icmp_hdr = (struct icmp *)packet;

    memset(packet, 0, PACKET_SIZE);

    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_cksum = 0;

    icmp_hdr->icmp_hun.ih_idseq.icd_id = htons(getpid());
    icmp_hdr->icmp_hun.ih_idseq.icd_seq = htons(1);
    //RTT stai scrivendo l'ora di partenza esatta (secondi e microsecondi) direttamente nel corpo del pacchetto che stai per inviare
    struct timeval *tv_payload = (struct timeval *)(packet + sizeof(struct icmp));
    gettimeofday(tv_payload, NULL);
    //checksum 
    icmp_hdr->icmp_cksum = checksum(packet, PACKET_SIZE);

    
    printf("Invio pacchetto...\n");
    if (sendto(s, packet, PACKET_SIZE, 0, (struct sockaddr*)dest_addr, sizeof(*dest_addr)) < 0) {
        perror("sendto fallito");
        close(s);
        freeaddrinfo(res);
        return 1;
    }

   
    char recv_buffer[1024]; // Buffer di ricezione 
    struct sockaddr_in reply_addr;
    socklen_t addr_len = sizeof(reply_addr);

    int n = recvfrom(s, recv_buffer, sizeof(recv_buffer), 0,
                     (struct sockaddr*)&reply_addr, &addr_len);

    if (n < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            printf("Host irraggiungibile (timeout)\n");
        } else {
            perror("recvfrom fallito");
        }
        close(s);
        freeaddrinfo(res);
        return 1;
    }

    printf("Ricevuti %d byte.\n", n);


    // --- 8. Analisi della Risposta ---
    
    // 1. Il buffer di ricezione inizia con un header IP.
    struct ip *ip_reply = (struct ip *)recv_buffer;
    
    // 2. La lunghezza dell'header IP è variabile!
    //    Il campo 'ip_hl' (header length) è in parole da 4 byte.
    int ip_header_len = ip_reply->ip_hl * 4;

    // 3. L'header ICMP si trova SUBITO DOPO l'header IP.
    struct icmp *icmp_reply = (struct icmp *)(recv_buffer + ip_header_len);

    // 4. Controlliamo se è una risposta al nostro ping
    if (icmp_reply->icmp_type == ICMP_ECHOREPLY) { // 0 = Echo Reply
        if (ntohs(icmp_reply->icmp_hun.ih_idseq.icd_id) == getpid()) {
            
            // È la nostra risposta! Calcoliamo l'RTT.
            struct timeval *tv_sent = (struct timeval *)(recv_buffer + ip_header_len + sizeof(struct icmp));
            struct timeval tv_now;
            gettimeofday(&tv_now, NULL);

            double rtt_ms = (tv_now.tv_sec - tv_sent->tv_sec) * 1000.0 +
                            (tv_now.tv_usec - tv_sent->tv_usec) / 1000.0;

            printf("Host %s è RAGGIUNGIBILE.\n", host);
            printf("RTT: %.3f ms\n", rtt_ms);

        } else {
            printf("Ricevuto Echo Reply, ma l'ID non corrisponde (ricevuto %d, atteso %d)\n",
                   ntohs(icmp_reply->icmp_hun.ih_idseq.icd_id), getpid());
        }
    } else {
        printf("Ricevuto pacchetto ICMP, ma non è un Echo Reply (tipo: %d)\n",
               icmp_reply->icmp_type);
    }
    
    // --- 9. Pulizia ---
    close(s);
    freeaddrinfo(res);
    return 0;
}

