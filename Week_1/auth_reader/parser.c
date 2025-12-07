# include "parser.h"
# include <string.h>
# include <ctype.h>
# include <stdio.h>


EventType detect_event_type(const char *line){
    if (strstr(line, "Failed password")){
        return EVENT_SSH_FAIL;
    }
    if (strstr(line, "Accepted password")){
        return EVENT_SSH_SUCCESS;
    }
    if (strstr(line, "Invalid user")){
        return EVENT_INVALID_USER;
    }
    if (strstr(line, "sudo") && strstr(line, "USER=root")){
        return EVENT_SUDO;
    }

    return EVENT_UNKNOWN;
}


int parse_line(const char *line, Event *ev){
    memset(ev, 0, sizeof(Event));
    strncpy(ev->raw, line, sizeof(ev->raw)-1);

    ev->type = detect_event_type(line);

    switch (ev->type){
        case EVENT_SSH_SUCCESS:
        case EVENT_SSH_FAIL:
            if (sscanf(line,
                "%*s %*s %*s %*s %*s %*s %*s for %63s from %63s port %d",
                ev->user, ev->ip, &ev->port) == 3){
                    return 1;
                }
            break;
        case EVENT_INVALID_USER:
        if (sscanf(line,
            "%*s %*s %*s %*s %*s %*s %*s Invalid user %63s from %63s port %d",
            ev->user, ev->ip, &ev->port) == 3){
                return 1;
            }
            break;
        case EVENT_SUDO:
            if (sscanf(line,
                "%*s %*s %*s %*s sudo: %63s",
                ev->user) == 1) {
                    strcpy(ev->ip, "-");
                    ev->port = 0;
                    return 1;
                }
                break;
        default:
                return 0;
    }
    return 0;
}


int is_valid_ipv4(const char *ip){
    int dots_count = 0;
    int num = 0;
    int length = 0;

    for (int i = 0; ip[i]; i++){

        if (ip[i] == '.'){

            if (length == 0 || num > 255){
                return 0;
            }

            dots_count++;
            num = 0;
            length = 0;
            continue;
        }

        if (!isdigit((unsigned char) ip[i])){
            return 0;
        }

        num = num * 10 + (ip[i] - '0');
        length++;
        if (length > 3){
            return 0;
        }
    }

    if (dots_count != 3 || num > 255 || length == 0){
        return 0;
    }

    return 1;

}


const char* event_type_to_string(EventType event){
    switch(event){
        case EVENT_SSH_FAIL: return "SSH_FAIL";
        case EVENT_SSH_SUCCESS: return "SSH_SUCCESS";
        case EVENT_INVALID_USER: return "INVALID_USER";
        case EVENT_SUDO: return "SUDO";
        default: return "UNKNOWN";
    }
}
