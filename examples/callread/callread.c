#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    char buffer[8];
    strcpy(buffer, "1234567");
    read(STDIN_FILENO, buffer, sizeof(buffer));
    buffer[7] = '\0';
    printf("%s\n", buffer);
    return 0;
}
