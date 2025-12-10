# include "stats.h"
# include <string.h>
# include <stdio.h>

void stats_init(Stats *s) {
    memset(s, 0, sizeof(Stats));
}

static void add_or_increment_ip(Stats *s, const char *ip){
    if (!ip || ip[0] == '\0'){
        return;
    }

    for (int i = 0; i < s->ip_count; i++){
        if (strcmp(s->ip_list[i].ip, ip) == 0){
            s->ip_list[i].count++;
            return;
        }
    }

    if (s->ip_count < 1024) {
        strncpy(s->ip_list[s->ip_count].ip, ip, sizeof(s->ip_list[s->ip_count].ip) - 1);
        s->ip_list[s->ip_count].count = 1;
        s->ip_count++;
    }
}

void stats_record_ip(Stats *s, const char *ip){
    add_or_increment_ip(s, ip);
}

void stats_update(Stats *s, const Event *ev){

    switch(ev->type) {
        case EVENT_SSH_FAIL:
            s->ssh_failed++;
            break;

        case EVENT_SSH_SUCCESS:
            s->ssh_success++;
            break;
        
        case EVENT_INVALID_USER:
            s->invalid_user++;
            break;
        
        case EVENT_SUDO:
            s->sudo_escalation++;
            break;
        
        default:
            return;
    }

    if (ev->ip && ev->ip[0] != '\0'){
        add_or_increment_ip(s, ev->ip);
    }
}

void stats_print(const Stats *s){
    printf("\n--- EVENT STATISTICS ---\n");
    printf("SSH failed attempts     : %d\n", s->ssh_failed);
    printf("SSH successful logins   : %d\n", s->ssh_success);
    printf("Invalid user attempts   : %d\n", s->invalid_user);
    printf("Sudo escalations        : %d\n", s->sudo_escalation);

    printf("\n--- IP STATISTICS ---\n");
    for (int i = 0; i < s->ip_count; i++) {
        printf("%-16s : %d\n", s->ip_list[i].ip, s->ip_list[i].count);
    }
}