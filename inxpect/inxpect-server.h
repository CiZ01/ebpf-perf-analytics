#ifndef __INXPECT_SERVER_H__
#define __INXPECT_SERVER_H__

#define PORT 8080
#define BUFFER_SIZE 1024

enum inxpect_server__message_type_t
{
    INXPECT_SERVER__MESSAGE_TYPE__EVENT_SET = 0,
    INXPECT_SERVER__MESSAGE_TYPE__EVENT_GET = 1,
    INXPECT_SERVER__MESSAGE_TYPE__SAMPLE_RATE_SET = 2,
    INXPECT_SERVER__MESSAGE_TYPE__PSECTION_GET = 3
};

union inxpect_server__message_return_t {
    int value;
    char *buffer;
};

struct inxpect_server__message_t
{
    int type;
    union inxpect_server__message_return_t return_value;
};

int inxpect_server__init_server(int port);
int inxpect_server__start_and_polling();
int handler();
void inxpect_server__close();

#endif // __INXPECT_SERVER_H__