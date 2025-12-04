# include <stdio.h>
# include <stdlib.h>

int main(void) {
    char buffer[255];
    FILE *fp = fopen("log.txt", "r");
    int line_counter = 0;
    
    if (fp == NULL)
    {
        fprintf(stderr, "File could not be opened.\n");
        return EXIT_FAILURE;
    }

    while (fgets(buffer, sizeof buffer, fp) != NULL)
    {
        line_counter++;
    }

    if (fclose(fp) == EOF)
    {
        fprintf(stderr, "Error while closing file.\n");
        return EXIT_FAILURE;
    }

    printf("The file has %i lines", line_counter);
    return 0;
}