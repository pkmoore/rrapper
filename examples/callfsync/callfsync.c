#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Fsync please!\n");
    fsync(1);
    return 0;
}
