typedef enum {
    EVENT_SSH_FAIL,
    EVENT_SSH_SUCCESS,
    EVENT_INVALID_USER,
    EVENT_SUDO,
    EVENT_UNKNOWN
} EventType;

typedef struct{
    EventType type;
    char user[64];
    char ip[64];
    int port;
    char raw[256];
} Event;

const char* event_type_to_string(EventType t);