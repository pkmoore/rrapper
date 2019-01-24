#include <unistd.h>

int main() {
    write(0, "test\n", 5);
    return 0;
}
