#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include <linux/if_link.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "inxpect.h"
#include "inxpect-server.h"

int server_fd, client_socket, opt = 1;
struct sockaddr_in address;
int addrlen = sizeof(address);
int BUFFSIZE = 512;

int inxpect_server__init_server(int port)
{
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        return -1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        return -1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons((port) ? port : PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        return -1;
    }
    return 0;
}

int inxpect_server__start_and_polling()
{
    fprintf(stdout, "[%s]: server started on address: %s:%d\n", INFO, inet_ntoa(address.sin_addr),
            ntohs(address.sin_port));

    // this is needed, if a client disconnets the server, it tries a new connection
    while (1)
    {
        if (listen(server_fd, 1) < 0)
        {
            perror("listen");
            return -1;
        }

        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
        {
            perror("accept");
            return -1;
        }

        handler();
    }

    return 0;
}

int handler()
{
    struct inxpect_server__message_t *message = {0};
    int err;
    char buff[BUFFSIZE];
    bzero(buff, BUFFSIZE);
    while (1)
    {
        err = recv(client_socket, buff, BUFFSIZE, 0);
        if (err < 0)
        {
            fprintf(stdout, "[%s]: occured during recv: %s\n", ERR, strerror(errno));
            break;
        }
        if (err == 0) // peer closed
        {
            fprintf(stdout, "[%s]: client disconnected\n", INFO);
            break;
        }

        message = (struct inxpect_server__message_t *)buff;

        fprintf(stdout, "[%s]: message type: %d\n", DEBUG, message->type);

        switch (message->type)
        {
        case INXPECT_SERVER__MESSAGE_TYPE__EVENT_SET:
            fprintf(stdout, "[%s]: event set: %d\n", INFO, message->value);
            // Preparazione del messaggio di risposta
            struct inxpect_server__message_t response_message;
            response_message.type = INXPECT_SERVER__MESSAGE_TYPE__RESPONSE + 88;

            // Allocazione e copia del buffer
            char response_buffer = 'A'; // Contenuto del buffer di risposta
            response_message.buffer = response_buffer;
            // response_message.buffer_length = strlen(response_buffer);

            if (send(client_socket, &response_message, sizeof(response_message), 0) < sizeof(response_message))
            {
                fprintf(stdout, "[%s]: occured during send: %s\n", ERR, strerror(errno));
            }
            //            free(message->buffer);
            break;
        case INXPECT_SERVER__MESSAGE_TYPE__EVENT_GET:
            fprintf(stdout, "[%s]: event get\n", INFO);
            break;
        case INXPECT_SERVER__MESSAGE_TYPE__SAMPLE_RATE_SET:
            fprintf(stdout, "[%s]: sample rate set\n", INFO);
            break;
        case INXPECT_SERVER__MESSAGE_TYPE__PSECTIONS_GET:
            fprintf(stdout, "[%s]: psection get\n", INFO);
            break;
        default:
            fprintf(stdout, "[%s]: unknown message type\n", INFO);
            break;
        }
    }
    return 0;
}

void inxpect_server__close()
{
    close(client_socket);
    close(server_fd);
}