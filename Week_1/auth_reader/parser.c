# include "parser.h"
# include <string.h>
# include <ctype.h>
# include <stdio.h>

/*PATTERNS TABLE*/

typedef struct 
{
    EventType type;
    const char *patterns[4];
} EventPatterns;

static EventPatterns event_patterns[] = {
    {EVENT_SSH_FAIL, {"Failed password", "authentification failure", NULL} },
    {EVENT_SSH_SUCCESS, {"Accepted password", NULL} },
    {EVENT_INVALID_USER, {"Invalid user", NULL} },
    {EVENT_SUDO, {"sudo", "USER=root", NULL} },
};


EventType detect_event_type(const char *line){
  for (size_t i = 0; i < sizeof(event_patterns)/sizeof(event_patterns[0]); i++) {
    for (int j = 0; event_patterns[i].patterns[j] != NULL; j++){
        if (strstr(line, event_patterns[i].patterns[j])){
            return event_patterns[i].type;
        }
    }
  }
  return EVENT_UNKNOWN;
}

static void parse_ssh_auth(const char *line, Event *ev){
    sscanf(line, "%*s %*s %*s %*s %*s %*s %*s for %63s from %63s port %d", ev->user, ev->ip, &ev->port);
}

static void parse_invalid_user(const char *line, Event *ev){
    sscanf(line, "%*s %*s %*s %*s %*s %*s %*s Invalid user %63s from %63s port %d", ev->user, ev->ip, &ev->port);
}

static void parse_sudo(const char *line, Event *ev){
    sscanf(line, "%*s %*s %*s %*s sudo: %63s", ev->user);

    if (ev->user[0] != '\0'){
        strcpy(ev->ip, "-");
        ev->port = 0;
    }
}

int parse_line(const char *line, Event *ev){
    memset(ev, 0, sizeof(Event));
    strncpy(ev->raw, line, sizeof(ev->raw)-1);

    ev->type = detect_event_type(line);

    switch (ev->type){
        case EVENT_SSH_SUCCESS:
        case EVENT_SSH_FAIL:
            parse_ssh_auth(line, ev);
            return 1;
        case EVENT_INVALID_USER:
            parse_invalid_user(line, ev);
            return 1;
        case EVENT_SUDO:
            parse_sudo(line, ev);
            return 1;
        default:
            return 0;
    }
    return 0;
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
