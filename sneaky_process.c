#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
  printf("sneaky_process pid = % d\n", getpid());
  //
}
