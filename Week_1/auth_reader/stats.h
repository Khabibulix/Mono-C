#ifndef STATS_H
#define STATS_H

# include "parser.h" // Event / EventType

typedef struct {
    int ssh_failed;
    int ssh_success;
    int invalid_user;
    int sudo_escalation;

    struct {
        char ip[64];
        int count;
    } ip_list[1024];

    int ip_count;

} Stats;

void stats_init(Stats *s);
void stats_update(Stats *s, const Event *ev);
void stats_record_ip(Stats *s, const char *ip);
void stats_record(const Stats *s);
void stats_print(const Stats *s);


#endif