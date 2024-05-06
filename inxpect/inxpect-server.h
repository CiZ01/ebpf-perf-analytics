#ifndef __INXPECT_SERVER_H__
#define __INXPECT_SERVER_H__

#define PORT 8080
#define BUFFER_SIZE 1024

enum inxpect_server__message_type_t
{
    INXPECT_SERVER__MESSAGE_TYPE__RESPONSE = 0, // server only
    INXPECT_SERVER__MESSAGE_TYPE__EVENT_SET = 1,
    INXPECT_SERVER__MESSAGE_TYPE__EVENT_GET = 2,
    INXPECT_SERVER__MESSAGE_TYPE__SAMPLE_RATE_SET = 3,
    INXPECT_SERVER__MESSAGE_TYPE__PSECTIONS_GET = 4
};

enum inxpect_server__message_error_t
{
    INXPECT_SERVER__MESSAGE_ERROR__NONE = 0,
    INXPECT_SERVER__MESSAGE_ERROR__UNKNOWN = 1,
    INXPECT_SERVER__MESSAGE_ERROR__INVALID = 2
};

struct inxpect_server__message_t
{
    int type;
    union {
        int value;
        char *buffer;
    };
};

int inxpect_server__init_server(int port);
int inxpect_server__start_and_polling();
int handler();
void inxpect_server__close();
int inxpect_server__event_set(int value);
int inxpect_server__event_get();
int inxpect_server__sample_rate_set(int value);
int inxpect_server__psections_get();

// ----- SERVER RESPONSES -----
const struct inxpect_server__message_t inxpect_server__response__ok = {INXPECT_SERVER__MESSAGE_TYPE__RESPONSE, 0};
const struct inxpect_server__message_t inxpect_server__response__bad_request = {INXPECT_SERVER__MESSAGE_TYPE__RESPONSE,
                                                                                1};
const struct inxpect_server__message_t inxpect_server__response__internal_error = {
    INXPECT_SERVER__MESSAGE_TYPE__RESPONSE, 2};
// ----------------------------

#endif // __INXPECT_SERVER_H__