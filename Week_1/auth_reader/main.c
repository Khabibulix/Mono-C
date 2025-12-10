# include <stdio.h>
# include <string.h>
# include <stdlib.h>

# include "parser.h"
# include "validator.h"
# include "stats.h"

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
    snprintf(array[*size].ip, sizeof(array[*size].ip), "%s", ip);
    array[*size].count = 1;
    (*size)++;
}


int main(void){
    Event ev;
    char buffer[255];
    Stats stats;
    stats_init(&stats);
    FILE *fp = fopen("fake_auth_log.txt", "r");


    if (fp == NULL){
        fprintf(stderr, "File could not be opened.\n");
        return EXIT_FAILURE;
    }

    while (fgets(buffer, sizeof buffer, fp) != NULL){

        if (!parse_line(buffer, &ev)){
            continue;
        }

        if (!validate_event(&ev)){
            continue;
        }

        const char *type_str = event_type_to_string(ev.type);
        printf("TYPE: %s | USER: %s | IP: %s | PORT: %d\n",
                type_str ? type_str : "UNKNOWN",
                ev.user ? ev.user : "(none)", 
                ev.ip ? ev.ip : "(none)", 
                ev.port);
        
        stats_update(&stats, &ev);
            
    }

    if (fclose(fp) == EOF){
        fprintf(stderr, "Error while closing file.\n");
        return EXIT_FAILURE;
    }

    stats_print(&stats);

    return 0;
}