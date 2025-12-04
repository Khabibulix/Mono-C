# include <stdio.h>
# include <string.h>
# include <stdlib.h>

int main(void){
    char buffer[255];
    FILE *fp = fopen("fake_auth_log.txt", "r");

    if (fp == NULL)
    {
        fprintf(stderr, "File could not be opened.\n");
        return EXIT_FAILURE;
    }

    while (fgets(buffer, sizeof buffer, fp) != NULL)
    {
        printf("%s", buffer);
    }

    if (fclose(fp) == EOF)
    {
        fprintf(stderr, "Error while closing file.\n");
        return EXIT_FAILURE;
    }

    return 0;
}