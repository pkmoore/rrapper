#include <stdio.h>

int main() {
  int res = rename("test/test.txt", "test/test2.txt");
  return 0;
}
