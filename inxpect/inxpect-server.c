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
int BUFFSIZE = 1024;

void __array_to_number_json(cJSON *array_json, void *array, int size, int type_size)
{
    cJSON *array_item;
    int len = size / type_size;
    for (int i = 0; i < len; i++)
    { // typeof is a gcc extension
        array_item = cJSON_CreateNumber(*(double *)array + (type_size * i));
        printf("[%s]: value: %llu", DEBUG, *(unsigned long long *)array + i);
        cJSON_AddItemToArray(array_json, array_item);
    }
}

void inxpect_server__message_to_json(struct inxpect_server__message_t *message, char *json)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "code", message->code);
    cJSON_AddNumberToObject(root, "value", message->value);

    if (message->buffer != NULL)
    {
        cJSON_AddStringToObject(root, "buffer", message->buffer);
    }
    else
    {
        cJSON_AddStringToObject(root, "buffer", "");
    }

    char *json_string = cJSON_Print(root);
    strcpy(json, json_string);

    fprintf(stdout, "[%s]: json: %s\n", INFO, json);
    fflush(stdout);

    cJSON_Delete(root);
    free(json_string);

    return;
}

void inxpect_server__json_to_message(char *json, struct inxpect_server__message_t *message)
{
    // safe init
    message->code = 0;
    message->value = 0;
    message->buffer = NULL;

    cJSON *root = cJSON_Parse(json);
    cJSON *code = cJSON_GetObjectItemCaseSensitive(root, "code");
    if (cJSON_IsNumber(code))
    {
        message->code = code->valueint;
    }

    cJSON *value = cJSON_GetObjectItemCaseSensitive(root, "value");
    if (cJSON_IsNumber(value))
    {
        message->value = value->valueint;
    }
    cJSON *buffer = cJSON_GetObjectItemCaseSensitive(root, "buffer");
    if (cJSON_IsObject(buffer))
    {
        message->buffer = malloc(strlen(cJSON_Print(buffer)) + 1);
        strcpy(message->buffer, cJSON_Print(buffer));
    }

    cJSON_Delete(root);

    return;
}

void inxpect_server__psection_to_json(struct psection_t *psection, char *json)
{
    cJSON *root = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "name", psection->record->name);
    cJSON *metrics = cJSON_CreateArray();

    for (int i = 0; i < MAX_METRICS; i++)
    {
        if (!psection->metrics[i])
        {
            break;
        }
        cJSON *array_item = cJSON_CreateObject();
        cJSON_AddStringToObject(array_item, "name", psection->metrics[i]->name);
        cJSON_AddNumberToObject(array_item, "code", psection->metrics[i]->code);
        cJSON_AddNumberToObject(array_item, "cpu", psection->metrics[i]->cpu);
        cJSON_AddNumberToObject(array_item, "enable", psection->metrics[i]->enabled);
        cJSON_AddNumberToObject(array_item, "reg_h", psection->metrics[i]->reg_h);

        cJSON_AddItemToArray(metrics, array_item);
    }

    cJSON_AddItemToObject(root, "metrics", metrics);

    char *json_string = cJSON_Print(root);
    strcpy(json, json_string);

    cJSON_Delete(root);
    free(json_string);
    return;
}

void inxpect_server__event_to_json(struct event *event, char *json)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "name", event->name);
    cJSON_AddNumberToObject(root, "cpu", event->cpu);
    cJSON_AddNumberToObject(root, "code", event->code);

    char *json_string = cJSON_Print(root);
    strcpy(json, json_string);

    cJSON_Delete(root);
    free(json_string);
    return;
}

int inxpect_server__init_server(int port)
{
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        return -1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
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

int sendMessage(int sock, struct inxpect_server__message_t msg)
{
    char buff[BUFFSIZE];
    inxpect_server__message_to_json(&msg, buff);
    return send(sock, buff, strlen(buff), 0);
}

int inxpect_response__unknown(int sock, struct inxpect_server__message_t *msg)
{
    msg->code = INXPECT_SERVER__MESSAGE_CODE__RESPONSE;
    msg->value = INXPECT_SERVER__MESSAGE_ERROR__UNKNOWN_CMD;
    msg->buffer = NULL;

    return sendMessage(sock, *msg);
}

int inxpect_response__event_set(int sock, struct inxpect_server__message_t *msg)
{
    /* request:
        code: 0,
        value: 0,
        buffer: {
            "name": "psection_name",
            "event": "event_name",
            "i_counter": counter index
        }
    */

    char buff[BUFFSIZE];
    int err = 0;
    cJSON *root = cJSON_Parse(msg->buffer);
    cJSON *psection_name = cJSON_GetObjectItemCaseSensitive(root, "name");
    cJSON *event_name = cJSON_GetObjectItemCaseSensitive(root, "event");
    cJSON *i_counter = cJSON_GetObjectItemCaseSensitive(root, "i_counter");

    if (!cJSON_IsString(psection_name) || !cJSON_IsString(event_name))
    {
        msg->code = INXPECT_SERVER__MESSAGE_CODE__RESPONSE;
        msg->value = INXPECT_SERVER__MESSAGE_ERROR__INVALID;
        msg->buffer = NULL;
        sendMessage(sock, *msg);
        cJSON_Delete(root);
        return -1;
    }

    if (!cJSON_IsNumber(i_counter))
    {
        msg->code = INXPECT_SERVER__MESSAGE_CODE__RESPONSE;
        msg->value = INXPECT_SERVER__MESSAGE_ERROR__INVALID;
        msg->buffer = NULL;
        sendMessage(sock, *msg);
        cJSON_Delete(root);
        return -1;
    }

    // find choosen psection
    struct psection_t *psection = psection__get_by_name(psection_name->valuestring);
    if (!psection)
    {
        msg->code = INXPECT_SERVER__MESSAGE_CODE__RESPONSE;
        msg->value = INXPECT_SERVER__MESSAGE_ERROR__INVALID;
        msg->buffer = NULL;
        sendMessage(sock, *msg);
        cJSON_Delete(root);
        return -1;
    }

    err = psection__change_event(psection, event_name->valuestring, i_counter->valueint);
    if (err)
    {
        msg->code = INXPECT_SERVER__MESSAGE_CODE__RESPONSE;
        msg->value = INXPECT_SERVER__MESSAGE_ERROR__INTERNAL;
        msg->buffer = NULL;
        sendMessage(sock, *msg);
        cJSON_Delete(root);
        return -1;
    }

    sendMessage(sock, *msg);
    cJSON_Delete(root);
    return 0;
}

int inxpect_response__psections_get(int sock, struct inxpect_server__message_t *msg)
{
    cJSON *psections_list = cJSON_CreateArray();
    struct psection_t *psection;
    // !! with this approch we are going out of the server's world
    char buff[BUFFSIZE];
    for (int i = 0; i < MAX_PSECTIONS; i++)
    {
        psection = &psections[i];
        if (psection->record)
        {
            inxpect_server__psection_to_json(psection, buff);
            cJSON_AddItemToArray(psections_list, cJSON_Parse(buff));
        }
    }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "code", INXPECT_SERVER__MESSAGE_CODE__PSECTIONS_GET);
    cJSON_AddNumberToObject(root, "value", INXPECT_SERVER__MESSAGE_ERROR__NONE);
    cJSON_AddItemToObject(root, "buffer", psections_list);

    char *json = cJSON_Print(root);
    fprintf(stdout, "[%s]: response: %s\n", INFO, json);
    fflush(stdout);
    send(sock, json, strlen(json), 0);
    cJSON_Delete(root);
    free(json);

    return 0;
}

int inxpect_response__sample_rate_set(int sock, struct inxpect_server__message_t *msg)
{
    if (msg->value == 0)
    {
        msg->code = INXPECT_SERVER__MESSAGE_CODE__RESPONSE;
        msg->value = INXPECT_SERVER__MESSAGE_ERROR__INVALID;
        msg->buffer = NULL;
        sendMessage(sock, *msg);
        return -1;
    }
    int err;
    err = sample_rate__set(prog_fd, msg->value);
    if (err)
    {
        msg->code = INXPECT_SERVER__MESSAGE_CODE__RESPONSE;
        msg->value = INXPECT_SERVER__MESSAGE_ERROR__INTERNAL;
        msg->buffer = NULL;
        sendMessage(sock, *msg);
        return -1;
    }

    msg->code = INXPECT_SERVER__MESSAGE_CODE__RESPONSE;
    msg->value = INXPECT_SERVER__MESSAGE_ERROR__NONE;
    msg->buffer = NULL;
    sendMessage(sock, *msg);
    return 0;
}

int inxpect_response__records_get_by_psection_name(int sock, struct inxpect_server__message_t *msg)
{
    cJSON *root = cJSON_Parse(msg->buffer);
    cJSON *psection_name = cJSON_GetObjectItemCaseSensitive(root, "name");
    if (!cJSON_IsString(psection_name))
    {
        msg->code = INXPECT_SERVER__MESSAGE_CODE__RESPONSE;
        msg->value = INXPECT_SERVER__MESSAGE_ERROR__INVALID;
        msg->buffer = NULL;
        sendMessage(sock, *msg);
        cJSON_Delete(root);
        return -1;
    }

    cJSON_Delete(root);

    struct record *record = record__get_by_psection_name(psection_name->valuestring);
    if (!record)
    {
        msg->code = INXPECT_SERVER__MESSAGE_CODE__RESPONSE;
        msg->value = INXPECT_SERVER__MESSAGE_ERROR__INTERNAL;
        msg->buffer = NULL;
        sendMessage(sock, *msg);
        cJSON_Delete(root);
        return -1;
    }

    msg->code = INXPECT_SERVER__MESSAGE_CODE__RESPONSE;
    msg->value = INXPECT_SERVER__MESSAGE_ERROR__NONE;

    cJSON *buffer_json = cJSON_CreateObject();
    cJSON_AddStringToObject(buffer_json, "name", record->name);

    cJSON *values = cJSON_CreateArray();
    for (int i = 0; i < MAX_METRICS; i++)
    {
        cJSON *array_item = cJSON_CreateNumber(record->values[i]);
        cJSON_AddItemToArray(values, array_item);
    }
    cJSON_AddItemToObject(buffer_json, "values", values);

    cJSON *run_counts = cJSON_CreateArray();
    for (int i = 0; i < MAX_METRICS; i++)
    {
        cJSON *array_item = cJSON_CreateNumber(record->run_cnts[i]);
        cJSON_AddItemToArray(run_counts, array_item);
    }
    cJSON_AddItemToObject(buffer_json, "run_counts", run_counts);

    cJSON *counters = cJSON_CreateArray();
    for (int i = 0; i < MAX_METRICS; i++)
    {
        cJSON *array_item = cJSON_CreateNumber(record->counters[i]);
        cJSON_AddItemToArray(counters, array_item);
    }
    cJSON_AddItemToObject(buffer_json, "counters", counters);

    msg->buffer = cJSON_Print(buffer_json);
    sendMessage(sock, *msg);

    cJSON_Delete(buffer_json);

    return 0;
}

int inxpect_response__records_get_all(int sock, struct inxpect_server__message_t *msg)
{
    struct record records[MAX_PSECTIONS] = {0};
    record__get_all(records);
    if (records[0].name[0] == '\0') // !! I don't know if this works
    {
        msg->code = INXPECT_SERVER__MESSAGE_CODE__RESPONSE;
        msg->value = INXPECT_SERVER__MESSAGE_ERROR__INTERNAL;
        msg->buffer = NULL;
        sendMessage(sock, *msg);
        return -1;
    }

    msg->code = INXPECT_SERVER__MESSAGE_CODE__RESPONSE;
    msg->value = INXPECT_SERVER__MESSAGE_ERROR__NONE;

    cJSON *buffer_json = cJSON_CreateArray();
    for (int i = 0; i < MAX_PSECTIONS; i++)
    {
        if (records[i].name[0] == '\0')
        {
            break;
        }
        cJSON *record_json = cJSON_CreateObject();
        cJSON_AddStringToObject(record_json, "name", records[i].name);

        cJSON *values = cJSON_CreateArray();
        for (int j = 0; j < MAX_METRICS; j++)
        {
            cJSON *array_item = cJSON_CreateNumber(records[i].values[j]);
            cJSON_AddItemToArray(values, array_item);
        }
        cJSON_AddItemToObject(record_json, "values", values);

        cJSON *run_counts = cJSON_CreateArray();
        for (int j = 0; j < MAX_METRICS; j++)
        {
            cJSON *array_item = cJSON_CreateNumber(records[i].run_cnts[j]);
            cJSON_AddItemToArray(run_counts, array_item);
        }
        cJSON_AddItemToObject(record_json, "run_counts", run_counts);

        cJSON *counters = cJSON_CreateArray();
        for (int j = 0; j < MAX_METRICS; j++)
        {
            cJSON *array_item = cJSON_CreateNumber(records[i].counters[j]);
            cJSON_AddItemToArray(counters, array_item);
        }
        cJSON_AddItemToObject(record_json, "counters", counters);

        cJSON_AddItemToArray(buffer_json, record_json);
    }

    msg->buffer = cJSON_Print(buffer_json);
    sendMessage(sock, *msg);

    cJSON_Delete(buffer_json);

    return 0;
}

int handler()
{
    struct inxpect_server__message_t *message = malloc(sizeof(struct inxpect_server__message_t));
    int err;
    char buff[BUFFSIZE];
    while (1)
    {
        bzero(buff, BUFFSIZE);
        err = recv(client_socket, buff, BUFFSIZE, 0);
        if (err < 0)
        {
            fprintf(stdout, "[%s]: occured during recv: %s\n", ERR, strerror(errno));
            free(message);
            break;
        }
        if (err == 0) // peer closed
        {
            fprintf(stdout, "[%s]: client disconnected\n", INFO);
            free(message);
            break;
        }

        fprintf(stdout, "[%s]: message received: %s\n", INFO, buff);

        inxpect_server__json_to_message(buff, message);

        fprintf(stdout, "[%s]: message received: code: %d\n value: %d\n buffer: %s \n", DEBUG, message->code,
                message->value, message->buffer);

        switch (message->code)
        {
        case INXPECT_SERVER__MESSAGE_CODE__EVENT_SET:
            inxpect_response__event_set(client_socket, message);
            break;
        case INXPECT_SERVER__MESSAGE_CODE__EVENT_GET:
            // inxpect_response__event_get(client_socket);
            break;
        case INXPECT_SERVER__MESSAGE_CODE__SAMPLE_RATE_SET:
            // inxpect_response__sample_rate_set(client_socket, message->value);
            break;
        case INXPECT_SERVER__MESSAGE_CODE__PSECTIONS_GET:
            inxpect_response__psections_get(client_socket, message);
            break;
        case INXPECT_SERVER__MESSAGE_CODE__RECORDS_GET:
            inxpect_response__records_get_all(client_socket, message);
            break;
        default:
            inxpect_response__unknown(client_socket, message);
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