#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>     // Per getpid()
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>   
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>  // Per inet_ntop
#include <netinet/ip.h> // Contiene la struct ip
#include <sys/time.h>   // Per gettimeofday e timeval   
#include <fcntl.h>      
#include <time.h>      
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netdb.h>      
#include <netinet/in.h> 
#include <poll.h>         
// --- COSTANTI PREDEFINITE ---
#define DEFAULT_BATCH 200       // Numero di porte da scansionare in parallelo se non specificato
#define DEFAULT_TIMEOUT_MS 300  // Tempo massimo di attesa (in millisecondi) per una risposta

// --- FUNZIONI DI UTILITÀ (HELPER) ---

/**
 * @brief Imposta un file descriptor (socket) in modalità non-bloccante.
 * @param fd Il file descriptor del socket.
 * @return 0 in caso di successo, -1 in caso di errore.
 *
 * Questa è una funzione CRUCIALE. In modalità non-bloccante, una chiamata a connect()
 * ritorna immediatamente invece di aspettare che la connessione sia stabilita.
 * Questo ci permette di lanciare centinaia di tentativi di connessione quasi istantaneamente.
 */
static int set_nonblocking(int fd) {
    // Ottiene i flag attuali del file descriptor
    int f = fcntl(fd, F_GETFL, 0);
    if (f == -1) return -1; // Errore nel leggere i flag
    // Aggiunge il flag O_NONBLOCK a quelli esistenti e li imposta
    return fcntl(fd, F_SETFL, f | O_NONBLOCK);
}

/**
 * @brief Imposta il numero di porta in una struttura di indirizzo generica.
 * @param ss Puntatore a una struct sockaddr_storage (può contenere sia IPv4 che IPv6).
 * @param port Il numero di porta da impostare.
 *
 * La funzione controlla la famiglia dell'indirizzo (AF_INET per IPv4 o AF_INET6 per IPv6)
 * per sapere quale campo della struttura modificare.
 */
static void set_port(struct sockaddr_storage *ss, int port) {
    if (ss->ss_family == AF_INET) { // Caso IPv4
        // Fa il cast al tipo corretto (sockaddr_in) e imposta la porta
        ((struct sockaddr_in*)ss)->sin_port = htons(port);
    } else if (ss->ss_family == AF_INET6) { // Caso IPv6
        // Fa il cast al tipo corretto (sockaddr_in6) e imposta la porta
        ((struct sockaddr_in6*)ss)->sin6_port = htons(port);
    }
    // htons() (Host TO Network Short) converte il numero di porta dall'ordine dei byte
    // del computer a quello standard di rete (obbligatorio).
}

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

void ping(const char *host) {
     if (getuid() != 0)
    {
        fprintf(stderr, " This program requires root privileges!\n");
        exit(EXIT_FAILURE);
    }

    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_RAW;

    int rv = getaddrinfo(host, NULL, &hints, &res);
    if (rv != 0) {
        // Se getaddrinfo fallisce, stampa un errore comprensibile e esce
        fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(rv));
        exit(1);
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
        exit(1);
    }

    struct timeval timeout;
    timeout.tv_sec = 3; // 3 secondi
    timeout.tv_usec = 0;
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt(SO_RCVTIMEO) fallito");
        close(s);
        freeaddrinfo(res);
        exit(1);
    }

    #define PACKET_SIZE 64
    char packet[PACKET_SIZE];
    struct icmp *icmp_hdr = (struct icmp *)packet;

    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_code = 0;

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
        exit(1);
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
        exit(1);
    }

    printf("Ricevuti %d byte.\n", n);

    struct ip *ip_reply = (struct ip *)recv_buffer;
    int ip_header_len = ip_reply->ip_hl * 4;
    // icmp header si trova subito dopo il nostro header ip
    struct icmp *icmp_reply = (struct icmp *)(recv_buffer + ip_header_len);

    if (icmp_reply->icmp_type == ICMP_ECHOREPLY) { // 0 = Echo Reply
        if (ntohs(icmp_reply->icmp_hun.ih_idseq.icd_id) == getpid()) {
            
            //Calcoliamo l'RTT.
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
                   perror("Exit");
                   exit(1);
        }
    } else {
        printf("Ricevuto pacchetto ICMP, ma non è un Echo Reply (tipo: %d)\n",
               icmp_reply->icmp_type);
               perror("Exit");
                exit(1);
    }
    
    
    close(s);
    freeaddrinfo(res);
    
}


// --- FUNZIONE PRINCIPALE ---
int main(int argc, char **argv) {
    // --- 1. PARSING DEGLI ARGOMENTI DELLA RIGA DI COMANDO ---
    if (argc < 4) {
        fprintf(stderr, "Utilizzo: %s <host> <porta_inizio> <porta_fine> [batch] [timeout_ms]\n", argv[0]);
        return 1;
    }

    const char *host = argv[1];
    ping(host);
    int start_port = atoi(argv[2]); // Converte la stringa della porta di inizio in un intero
    int end_port = atoi(argv[3]);   // Converte la stringa della porta di fine in un intero
    // Usa l'operatore ternario per impostare valori di default se non forniti
    int batch = (argc > 4) ? atoi(argv[4]) : DEFAULT_BATCH;
    int timeout_ms = (argc > 5) ? atoi(argv[5]) : DEFAULT_TIMEOUT_MS;

    // Controlli di validità sui valori inseriti
    if (start_port < 0) start_port = 0;
    if (end_port < start_port) end_port = start_port;
    if (batch < 1) batch = DEFAULT_BATCH;

    // --- 2. RISOLUZIONE DEL NOME HOST (DNS LOOKUP) ---
    // Prepara la struct 'hints' per guidare getaddrinfo()
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;     // Accetta sia indirizzi IPv4 (AF_INET) che IPv6 (AF_INET6)
    hints.ai_socktype = SOCK_STREAM; // Vogliamo una connessione di tipo TCP
    hints.ai_flags = AI_ADDRCONFIG;  // Restituisce indirizzi solo se abbiamo una configurazione di rete per quella famiglia

    // Esegue la risoluzione DNS
    int rv = getaddrinfo(host, NULL, &hints, &res);
    if (rv != 0) {
        // Se getaddrinfo fallisce, stampa un errore comprensibile e esce
        fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(rv));
        return 1;
    }

    // --- 3. COPIA DEGLI INDIRIZZI IN ARRAY PER UN FACILE ACCESSO ---
    // Conta quanti indirizzi sono stati trovati
    int addr_count = 0;
    for (struct addrinfo *p = res; p; p = p->ai_next) addr_count++;
    if (addr_count == 0) { freeaddrinfo(res); fprintf(stderr,"Nessun indirizzo trovato per l'host\n"); return 1; }

    // Alloca memoria per i nostri array che conterranno gli indirizzi e le loro dimensioni
    struct sockaddr_storage *addrs = calloc(addr_count, sizeof(*addrs));
    socklen_t *addrlens = calloc(addr_count, sizeof(*addrlens));
    if (!addrs || !addrlens) { perror("calloc"); freeaddrinfo(res); return 1; }

    // Scorre la lista concatenata di getaddrinfo e copia i dati nei nostri array
    int ai = 0;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        memcpy(&addrs[ai], p->ai_addr, p->ai_addrlen); // Copia la struttura dell'indirizzo
        addrlens[ai] = p->ai_addrlen;                 // Copia la sua dimensione
        ai++;
    }
    freeaddrinfo(res); // Libera la memoria allocata da getaddrinfo, non ci serve più

    // --- 4. CICLO DI SCANSIONE PRINCIPALE ---
    // Ciclo esterno: itera su ogni indirizzo IP trovato per l'host
    for (int a = 0; a < addr_count; ++a) {
        printf("Scansione IP %d/%d\n", a+1, addr_count);
        int port = start_port;

        // Ciclo interno: continua finché ci sono porte da scansionare per questo IP
        while (port <= end_port) {
            // --- 4a. PREPARAZIONE DEL BATCH CORRENTE ---
            // Calcola la dimensione del blocco corrente.
            // Se le porte rimaste sono meno della dimensione del batch, usa il numero di porte rimaste.
            int remaining_ports = end_port - port + 1;
            int this_batch = (remaining_ports < batch) ? remaining_ports : batch;

            // Alloca memoria per gli array necessari a gestire questo batch
            struct pollfd *pfds = calloc(this_batch, sizeof(*pfds));   // Per la funzione poll()
            int *fds = calloc(this_batch, sizeof(int));               // Per i file descriptor dei socket
            int *ports = calloc(this_batch, sizeof(int));             // Per ricordare la porta associata a ogni socket
            struct sockaddr_storage *ss_arr = calloc(this_batch, sizeof(*ss_arr)); // Per gli indirizzi di destinazione
            socklen_t *ss_len = calloc(this_batch, sizeof(*ss_len));   // Per le dimensioni degli indirizzi

            if (!pfds || !fds || !ports || !ss_arr || !ss_len) {
                perror("calloc fallito durante la preparazione del batch");
                // Pulizia generale prima di uscire
                free(pfds); free(fds); free(ports); free(ss_arr); free(ss_len);
                free(addrs); free(addrlens);
                return 1;
            }

            // --- 4b. CREAZIONE DEI SOCKET E AVVIO DELLE CONNESSIONI PER IL BATCH ---
            for (int i = 0; i < this_batch; ++i, ++port) {
                // Popola gli array con i dati per la connessione corrente
                ports[i] = port;
                ss_arr[i] = addrs[a]; // Copia la struttura dell'indirizzo base
                ss_len[i] = addrlens[a];
                set_port(&ss_arr[i], port); // Imposta la porta specifica per questo tentativo

                // Crea il socket
                int s = socket(ss_arr[i].ss_family, SOCK_STREAM, 0);
                fds[i] = -1;      // Inizializza a -1 (nessun socket valido)
                pfds[i].fd = -1;  // Inizializza a -1 (poll ignorerà questo elemento)
                pfds[i].events = POLLOUT; // Vogliamo essere notificati quando il socket è scrivibile (connessione completata)
                pfds[i].revents = 0;      // Campo per i risultati di poll, lo azzeriamo

                if (s < 0) {
                    fprintf(stderr, "%s:%d socket() fallito: %s\n", host, port, strerror(errno));
                    continue; // Passa alla prossima porta del batch
                }
                if (set_nonblocking(s) < 0) {
                    fprintf(stderr, "%s:%d fcntl(non-blocking) fallito: %s\n", host, port, strerror(errno));
                    close(s);
                    continue; // Passa alla prossima porta del batch
                }

                // Tenta la connessione (non-bloccante)
                int c = connect(s, (struct sockaddr*)&ss_arr[i], ss_len[i]);
                if (c == 0) {
                    // Raro, ma possibile: connessione stabilita immediatamente.
                    printf("%s:%d -> APERTA (immediata)\n", host, port);
                    close(s); // Chiudiamo subito il socket
                } else {
                    if (errno == EINPROGRESS) {
                        // Caso normale: la connessione è in corso in background.
                        // Salviamo il file descriptor per monitorarlo con poll().
                        fds[i] = s;
                        pfds[i].fd = s;
                    } else {
                        // Errore immediato (es. connessione rifiutata dal sistema locale).
                        printf("%s:%d -> CHIUSA (errore immediato: %s)\n", host, port, strerror(errno));
                        close(s); // Chiudiamo il socket
                    }
                }
            }

            // --- 4c. ATTESA CON POLL() ---
            // Conta quanti socket stiamo effettivamente monitorando
            int watch = 0;
            for (int i = 0; i < this_batch; ++i) if (pfds[i].fd != -1) watch++;

            if (watch > 0) { // Se c'è almeno un socket da monitorare
                // Chiamata bloccante a poll(): attende un evento o lo scadere del timeout
                int ret = poll(pfds, this_batch, timeout_ms);
                if (ret < 0) perror("poll"); // Errore in poll()

                // --- 4d. ANALISI DEI RISULTATI DOPO POLL() ---
                for (int i = 0; i < this_batch; ++i) {
                    int sfd = fds[i]; // Il file descriptor del socket
                    int prt = ports[i]; // La porta associata

                    if (sfd == -1) continue; // Se non c'era un socket valido per questo indice, salta

                    // Controlla il campo 'revents' riempito da poll()
                    if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                        // Si è verificato un errore sul socket. Per sapere quale, usiamo getsockopt.
                        int soerr = 0; socklen_t len = sizeof(soerr);
                        getsockopt(sfd, SOL_SOCKET, SO_ERROR, &soerr, &len);
                        printf("%s:%d -> CHIUSA (errore sul socket: %s)\n", host, prt, strerror(soerr));
                        close(sfd);
                    } else if (pfds[i].revents & POLLOUT) {
                        // Il socket è diventato scrivibile: la connessione è terminata (con successo o fallimento).
                        // Usiamo getsockopt per distinguere i due casi.
                        int soerr = 0; socklen_t len = sizeof(soerr);
                        if (getsockopt(sfd, SOL_SOCKET, SO_ERROR, &soerr, &len) < 0) {
                             printf("%s:%d -> ERRORE getsockopt: %s\n", host, prt, strerror(errno));
                        } else if (soerr == 0) {
                            // Nessun errore: connessione riuscita!
                            printf("%s:%d -> APERTA\n", host, prt);
                        } else {
                            // C'è un errore (es. ECONNREFUSED): connessione fallita.
                            printf("%s:%d -> CHIUSA (errore: %s)\n", host, prt, strerror(soerr));
                        }
                        close(sfd);
                    } else {
                        // Nessun evento per questo socket dopo il timeout.
                        printf("%s:%d -> FILTRATA/NESSUNA RISPOSTA (timeout %d ms)\n", host, prt, timeout_ms);
                        close(sfd);
                    }
                }
            }

            // --- 4e. PULIZIA DELLA MEMORIA DEL BATCH ---
            // Libera la memoria allocata all'inizio del ciclo 'while' per il batch corrente.
            free(pfds); free(fds); free(ports); free(ss_arr); free(ss_len);
        } // Fine del ciclo 'while' per le porte
    } // Fine del ciclo 'for' per gli IP

    // --- 5. PULIZIA FINALE ---
    // Libera la memoria allocata all'inizio per la lista degli indirizzi.
    free(addrs); free(addrlens);
    return 0; // Uscita con successo
}