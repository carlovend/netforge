
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>

#define PORT "8080"
#define BACKLOG 10
#define BUF_SIZE 4096

static void fatal(const char *msg){ perror(msg); exit(1); }

int main(void) {
    struct addrinfo hints, *servinfo, *p;
    int rv, listener = -1, yes = 1;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;          // forza IPv4 per evitare ::1 vs 127.0.0.1
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0) continue;

        if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
            fatal("setsockopt");

        if (bind(listener, p->ai_addr, p->ai_addrlen) == -1) {
            close(listener);
            listener = -1;
            continue;
        }
        break;
    }
    freeaddrinfo(servinfo);
    if (listener < 0) fatal("bind");

    if (listen(listener, BACKLOG) == -1) fatal("listen");

    printf("server: listening on port %s\n", PORT);

    // pfds[0] = listener; altri saranno client.
    struct pollfd pfds[1024];
    int nfds = 1;
    pfds[0].fd = listener;
    pfds[0].events = POLLIN;

    char buf[BUF_SIZE];

    for (;;) {
        int nready = poll(pfds, nfds, -1);
        if (nready < 0) fatal("poll");

        // 1) nuove connessioni?
        if (pfds[0].revents & POLLIN) {
            struct sockaddr_storage their_addr;
            socklen_t addrlen = sizeof their_addr;
            int newfd = accept(listener, (struct sockaddr*)&their_addr, &addrlen);
            if (newfd == -1) {
                perror("accept");
            } else {
                if (nfds >= (int)(sizeof(pfds)/sizeof(pfds[0]))) {
                    fprintf(stderr, "Too many clients\n");
                    close(newfd);
                } else {
                    pfds[nfds].fd = newfd;
                    pfds[nfds].events = POLLIN;
                    nfds++;
                    printf("server: new connection on fd %d (total=%d)\n", newfd, nfds-1);
                }
            }
            if (--nready == 0) continue;
        }

        // 2) dati dai client
        for (int i = 1; i < nfds && nready > 0; i++) {
            if (!(pfds[i].revents & (POLLIN | POLLERR | POLLHUP))) continue;

            int fd = pfds[i].fd;

            // lettura
            int num = recv(fd, buf, BUF_SIZE - 1, 0);
            if (num <= 0) {
                if (num == 0) printf("server: fd %d closed by peer\n", fd);
                else perror("recv");
                close(fd);

                // rimuovi compatto pfds[i]
                pfds[i] = pfds[nfds - 1];
                nfds--;
                i--; // rimani sulla stessa i per verificare l'elemento spostato
            } else {
                buf[num] = '\0';
                printf("server: received from fd %d: \"%s\"\n", fd, buf);

                // echo di risposta
                ssize_t sent = send(fd, buf, (size_t)num, 0);
                if (sent == -1) {
                    perror("send");
                    close(fd);
                    pfds[i] = pfds[nfds - 1];
                    nfds--;
                    i--;
                }
            }
            nready--;
        }
    }
    return 0;
}
