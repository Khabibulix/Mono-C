# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <ctype.h> //isdigit
# include "parser.h"


struct IpCount {
    char ip[64];
    int count;
};


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

        printf("TYPE: %s | USER: %s | IP: %s | PORT: %d\n",
                event_type_to_string(ev.type),
                ev.user, 
                ev.ip, 
                ev.port);
        
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