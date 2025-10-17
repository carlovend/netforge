#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#define PORT "8080"
#define BACKLOG 10
#define BUF_SIZE 1024

int main(void)  {
    struct addrinfo hints, *servinfo, *p;
    int sockfd, new_fd;
    int yes = 1;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;         // solo IPv4
    hints.ai_socktype = SOCK_STREAM;   // TCP
    hints.ai_flags = AI_PASSIVE;       // usa il mio IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // ciclo sugli indirizzi fino a bind() riuscito
    for (p = servinfo; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    struct sockaddr_storage client_addr;
    socklen_t addr_size = sizeof client_addr;

    new_fd = accept(sockfd, (struct sockaddr*)&client_addr, &addr_size);
    if (new_fd == -1) {
        perror("accept");
        exit(1);
    }

    printf("server: got a connection!\n");

    // ricevi e stampa il messaggio
    char buf[BUF_SIZE];
    int numbytes = recv(new_fd, buf, BUF_SIZE - 1, 0);
    if (numbytes == -1) {
        perror("recv");
        exit(1);
    }

    buf[numbytes] = '\0';
    printf("server: received '%s'\n", buf);

    close(new_fd);
    close(sockfd);
    return 0;
}
