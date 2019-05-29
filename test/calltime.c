#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

int main(void) {
  time_t rawtime;
  struct tm * timeinfo;

  time (&rawtime);
  timeinfo = localtime (&rawtime);
  printf ("Current local time and date: %s", asctime(timeinfo));

  sleep(3);

  time (&rawtime);
  timeinfo = localtime (&rawtime);
  printf ("Current local time and date: %s", asctime(timeinfo));

  sleep(5);

  time (&rawtime);
  timeinfo = localtime (&rawtime);
  printf ("Current local time and date: %s", asctime(timeinfo));
  
  return 0;
}