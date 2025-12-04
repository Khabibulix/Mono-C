# include <stdio.h>
# include <string.h>
# include <stdlib.h>


int main(void){
    char buffer[255];
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
        printf("Possible bruteforce detected!");
    }

    return 0;
}