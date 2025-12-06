# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <ctype.h> //isdigit

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


// Jan 31 07:12:03 debian sshd[1502]: Accepted password for bob from 192.168.1.55 port 52341 ssh2
// --> 192.168.1.55
char *extract_ip_from_line(const char *line, char *out){
    const char *pointer_for_from = strstr(line, " from");
    if (!pointer_for_from) {
        out[0] = '\0';
        return NULL;
    }

    pointer_for_from += 6;
    int index = 0;

    while ( ( pointer_for_from[index] >= '0' && pointer_for_from[index] <= '9') || pointer_for_from[index] == '.') {
        out[index] = pointer_for_from[index];
        index++;
    } 

    out[index] = '\0';
    return out;
}



int main(void){
    char buffer[255];
    char ip[64];
    struct IpCount ip_stats[1024];
    int ip_stats_size = 0;
    FILE *fp = fopen("fake_auth_log.txt", "r");
    int ssh_failed_password_attempts = 0;
    int ssh_success_password_attempts = 0;
    int invalid_user_connection = 0;
    int sudo_escalations = 0;


    if (fp == NULL){
        fprintf(stderr, "File could not be opened.\n");
        return EXIT_FAILURE;
    }

    while (fgets(buffer, sizeof buffer, fp) != NULL){
        if (strstr(buffer, "Failed password")){
            ssh_failed_password_attempts++;
        } else if (strstr(buffer, "Accepted password")){
            ssh_success_password_attempts++;
        } else if (strstr(buffer, "Invalid user")){
            invalid_user_connection++;
        } else if (strstr(buffer, "sudo") && strstr(buffer, "user root")){
            sudo_escalations++;
        }

        if (extract_ip_from_line(buffer, ip) && is_valid_ipv4(ip)){
            add_or_increment(ip_stats, &ip_stats_size, ip);
        }
    }

    if (fclose(fp) == EOF){
        fprintf(stderr, "Error while closing file.\n");
        return EXIT_FAILURE;
    }

    printf("Failed ssh connections: %d\n", ssh_failed_password_attempts); 
    printf("Successful ssh connections: %d\n", ssh_success_password_attempts);
    printf("Invalid user conns attempts: %d\n", invalid_user_connection);
    printf("Sudo Escalations: %d\n", sudo_escalations);

    if (ssh_failed_password_attempts > 10){
        printf("Possible bruteforce detected!\n");
    }

    printf("--- IP STATS ---\n");
    for (int i = 0; i < ip_stats_size; i++){
        printf("%s -> %d fois\n", ip_stats[i].ip, ip_stats[i].count);
    }

    return 0;
}