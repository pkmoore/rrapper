#include <unistd.h>

int main() {
  getpid();
  int result = write(1, "hello\n", 6);
  result = write(1, "test again\n", 11);
  if(result != 5) {
    write(1, "failed", 6);
  }
  return 0;
}
