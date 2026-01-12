#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int win() {
    system("/bin/sh");
}

int main() {
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);

    char buf[0x10] = {0};

    puts("What is your name: ");
    gets(buf);

    if (strlen(buf) >= 0x10-1) {
        puts("Thats suspicious.");
        exit(1);
    }

    printf("Hi, %s!\n", buf);
}