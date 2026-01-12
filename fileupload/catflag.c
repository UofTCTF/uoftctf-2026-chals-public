#include <stdio.h>

int main(void) {
    const char *path = "/flag.txt";
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return 1;
    }

    int c;
    while ((c = fgetc(f)) != EOF) {
        putchar(c);
    }

    fclose(f);
    return 0;
}