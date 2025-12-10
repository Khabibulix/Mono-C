# include "parser.h"
# include <string.h>
# include <ctype.h>
# include <stdio.h>

static void parse_ssh_auth(const char *line, Event *ev);
static void parse_invalid_user(const char *line, Event *ev);
static void parse_sudo(const char *line, Event *ev);

//-----------------------Structures----------------------------------------------------------------------

static const char *event_names[] = {
    [EVENT_SSH_FAIL] = "SSH_FAIL",
    [EVENT_SSH_SUCCESS] = "SSH_SUCCESS",
    [EVENT_INVALID_USER] = "INVALID_USER",
    [EVENT_SUDO] = "SUDO",
    [EVENT_UNKNOWN] = "UNKNOWN"
};

typedef struct 
{
    EventType type;
    const char *patterns[4];
    void (*parse_fn)(const char *line, Event *ev);
} ParseRule;

static ParseRule parse_rules[] = {
    {EVENT_SSH_FAIL,
        {"Failed password", "authentification failure", NULL}, 
        parse_ssh_auth },

    {EVENT_SSH_SUCCESS,
        {"Accepted password", NULL},
        parse_ssh_auth },

    {EVENT_INVALID_USER,
        {"Invalid user", NULL},
        parse_invalid_user },

    {EVENT_SUDO,
        {"sudo", "USER=root", NULL},
        parse_sudo }
};


//-----------------------Functions----------------------------------------------------------------------

int detect_event_rule(const char *line){
  for (size_t i = 0; i < sizeof(parse_rules)/sizeof(parse_rules[0]); i++) {
    for (int j = 0; parse_rules[i].patterns[j] != NULL; j++){
        if (strstr(line, parse_rules[i].patterns[j])){
            return i;
        }
    }
  }
  return -1;
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

    int rule_index = detect_event_rule(line);
    if (rule_index < 0){
        return 0;
    }

    ev->type = parse_rules[rule_index].type;
    parse_rules[rule_index].parse_fn(line, ev);

    return 1;
}

const char* event_type_to_string(EventType event){
    return event_names[event] ? event_names[event] : "UNKNOWN";
}
