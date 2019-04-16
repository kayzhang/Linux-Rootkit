#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
  int fd = open("hello-5.c", 0);

  char path[NAME_MAX];
  memset(path, '\0', sizeof(path));
  sprintf(path, "%s%d", "/proc/self/fd/", fd);

  char buffer[NAME_MAX];
  memset(buffer, '\0', sizeof(buffer));

  readlink(path, buffer, sizeof(buffer));

  printf("The file path is: %s\n", buffer);

  printf("CWD is: %s\n", getcwd(buffer, sizeof(buffer)));

  return EXIT_SUCCESS;
}
