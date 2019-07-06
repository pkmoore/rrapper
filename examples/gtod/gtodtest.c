#include <stdio.h>
#include <time.h>

int main() {
  time_t t;
  t = time(NULL);
  printf("%ld\n", t);
  t = 0;
  time(&t);
  printf("%ld\n", t);
  return 0;
}
