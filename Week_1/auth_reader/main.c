# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <ctype.h> //isdigit

typedef enum {
    EVENT_SSH_FAIL,
    EVENT_SSH_SUCCESS,
    EVENT_INVALID_USER,
    EVENT_SUDO,
    EVENT_UNKNOWN
} EventType;

typedef struct {
    EventType type;
    char user[64];
    char ip[64];
    int port;
    char raw[256];
} Event;

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

struct IpCount {
    char ip[64];
    int count;
};

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

void add_or_increment(struct IpCount *array, int *size, const char *ip){
    for (int i = 0; i < *size; i++){
        if (strcmp(array[i].ip, ip) == 0){
            array[i].count++;
            return;
        }
    }

    strcpy(array[*size].ip, ip);
    array[*size].count = 1;
    (*size)++;
}


int main(void){
    Event ev;
    char buffer[255];
    struct IpCount ip_stats[1024];
    int ssh_failed_password_attempts = 0;
    int ssh_success_password_attempts = 0;
    int invalid_user_connections = 0;
    int sudo_escalations = 0;
    int ip_stats_size = 0;
    FILE *fp = fopen("fake_auth_log.txt", "r");


    if (fp == NULL){
        fprintf(stderr, "File could not be opened.\n");
        return EXIT_FAILURE;
    }

    while (fgets(buffer, sizeof buffer, fp) != NULL){
        if (!parse_line(buffer, &ev)){
            continue;
        }

        printf("TYPE: %d | USER: %s | IP: %s | PORT: %d\n",
                ev.type, ev.user, ev.ip, ev.port);
        
        switch(ev.type){
            case EVENT_SSH_FAIL:
                ssh_failed_password_attempts++;
                break;
            case EVENT_SSH_SUCCESS:
                ssh_success_password_attempts++;
                break;
            case EVENT_INVALID_USER:
                invalid_user_connections++;
                break;
            case EVENT_SUDO:
                sudo_escalations++;
                break;
            default:
                break;
        }

        if (is_valid_ipv4(ev.ip)) {
            add_or_increment(ip_stats, &ip_stats_size, ev.ip);
        }


    
    }

    if (fclose(fp) == EOF){
        fprintf(stderr, "Error while closing file.\n");
        return EXIT_FAILURE;
    }

    printf("--- IP STATS ---\n");
    for (int i = 0; i < ip_stats_size; i++){
        printf("%s -> %d fois\n", ip_stats[i].ip, ip_stats[i].count);
    }

    return 0;
}