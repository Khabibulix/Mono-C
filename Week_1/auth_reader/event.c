# include "event.h"
# include <string.h>

static const char *event_names[] = {
    [EVENT_SSH_FAIL] = "SSH_FAIL",
    [EVENT_SSH_SUCCESS] = "SSH_SUCCESS",
    [EVENT_INVALID_USER] = "INVALID_USER",
    [EVENT_SUDO] = "SUDO",
    [EVENT_UNKNOWN] = "UNKNOWN"
};

const char* event_type_to_string(EventType event){
    return event_names[event] ? event_names[event] : "UNKNOWN";
}
