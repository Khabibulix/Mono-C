# include <stdio.h>
# include <stdlib.h>
# include <string.h>

int main(void) {
    char buffer[255];
    FILE *fp = fopen("log.txt", "r");
    
    if (fp == NULL)
    {
        fprintf(stderr, "File could not be opened.\n");
        return EXIT_FAILURE;
    }

    while (fgets(buffer, sizeof buffer, fp) != NULL)
    {
        if (strstr(buffer, "ERROR") || strstr(buffer, "WARN") )
        {
            printf("%s",buffer);
        }
    }

    if (fclose(fp) == EOF)
    {
        fprintf(stderr, "Error while closing file.\n");
        return EXIT_FAILURE;
    }

    return 0;
}