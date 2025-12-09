# include <stdio.h>
# include <string.h>
# include <ctype.h>
# include "validator.h"

static int is_valid_username(const char *user){
    if (!user || user[0] == '\0'){
        return 0;
    }
    for (int i = 0; user[i]; i++){
        if (!isalnum(user[i]) && user[i] != '_' && user[i] != '-' && user[i] != '.'){
            return 0;
        }
    }
    return 1;
}

static int is_valid_ipv4(const char *ip){
    if (ip == NULL || *ip == '\0'){
        return 0;
    }

    char buf[32];
    size_t len = strlen(ip);

    // Ipv4 mas length is '255.255.255.255'
    if (len < 7 || len > 15){
        return 0;
    }

    //Force Null termination after copy
    strncpy(buf, ip, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *p = buf;
    int segments = 0;

    while (*p){
        
        if (!isdigit((unsigned char)*p)){
            return 0;
        }

        //No leading zeroes
        if (*p == '0' && isdigit((unsigned char)*(p+1))){
            return 0;
        }

        int num = 0;
        int digits = 0;

        while(isdigit((unsigned char)*p)){
            num = num * 10 + (*p - '0');
            if (num > 255){
                return 0;
            }

            digits++;
            if (digits > 3){
                return 0;
            }

            p++;
        }

        segments++;

        //No trailing dots
        if (*p == '.') {
            if (segments >= 4) {
                return 0;
            }
            p++;
            continue;
        }

        if (*p == '\0'){
            break;
        }

        return 0;
    }

    return (segments == 4);
}

static int is_valid_port(int port){
    return port > 0 && port <= 65535;
}

int validate_event(const Event *ev){
    if (!ev){
        return 0;
    }

    switch (ev->type){
        case EVENT_SSH_FAIL:
        case EVENT_SSH_SUCCESS:
        case EVENT_INVALID_USER:
            if (!is_valid_username(ev->user)){
                return 0;
            }
            if (!is_valid_ipv4(ev->ip)){
                return 0;
            }
            if (!is_valid_port(ev->port)){
                return 0;
            }
            break;

        case EVENT_SUDO:
            if (!is_valid_username(ev->user)){
                return 0;
            }
            break;
        
            case EVENT_UNKNOWN:
                break;
    }

    return 1;

}