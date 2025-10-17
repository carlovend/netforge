#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define PORT "8080"
#define BUF_SIZE 1024

int main(void) {
    struct addrinfo hints, *res, *p;
    int sockfd;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;     // AF_INET o AF_INET6
    hints.ai_socktype = SOCK_STREAM; // TCP

    //Risolve "localhost" nella lista di indirizzi disponibili
    if ((rv = getaddrinfo("localhost", PORT, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    //Prova tutti gli indirizzi finché connect() riesce
    for (p = res; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("client: connect");
            close(sockfd);
            continue;
        }

        break; // connessione riuscita
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    freeaddrinfo(res); // non serve più

    printf("client: connected to server!\n");

    //Invia un messaggio


    char msg[] = "Ciao server!\n";
    if (send(sockfd, msg, strlen(msg), 0) == -1) {
        perror("send");
        exit(1);
    }

    //Ricevi eventuale risposta
    char buf[BUF_SIZE];
    int numbytes = recv(sockfd, buf, BUF_SIZE - 1, 0);
    if (numbytes == -1) {
        perror("recv");
        exit(1);
    }
    buf[numbytes] = '\0';
    printf("client: received '%s'\n", buf);

    close(sockfd);
    return 0;
}
