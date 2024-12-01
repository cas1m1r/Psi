/** 				ψ kernel module 			**/
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/fs.h>
#include "hooks.h"

// Module Defs 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("tyl3rdurd3n");
MODULE_DESCRIPTION("Using malware to find malware.");
MODULE_VERSION("0.42");

// stuff for logging
#define PSILOG "/tmp/.psi.log"
#define BLK_SZ 42

static loff_t BLK_CNT;

/* Function Prototypes */
static int 		__init psi_start(void);
static void 	__exit psi_stop(void);

// custom types for holding original syscalls (taken from reveng_rtkit)
typedef asmlinkage long(*tt_syscall)(const struct pt_regs*);
static tt_syscall original_sys_open;
static tt_syscall original_execve;
static tt_syscall original_umask;
static tt_syscall original_chmod; 
static tt_syscall original_chown;

/* Hooking basics */
unsigned long cr0;

static inline void overwrite_cr0(unsigned long val){
	unsigned long __force_order;
	// Applying inline assembly (extended) to write to cr0 register
	// taken from implementaton in reveng_rtkit
	asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

/* Page Protection Enable/Disable */
static inline void disable_write_protection(void){
	unsigned long __force_order;
	// Applying inline assembly (extended) to write to cr0 register
	// taken from implementaton in reveng_rtkit
	overwrite_cr0(cr0 & ~0x00010000);
}

static void enable_write_protection(void){
	overwrite_cr0(cr0);
}

// utility function for logging events to disk
loff_t psi_print(char* data, int datasize, loff_t pos){
	struct file* fp;
	int i;
	int n_blocks = (int) datasize/BLK_SZ;			// check data size before writing 

	// loff_t pos = 0;

	fp = filp_open(PSILOG, O_WRONLY|O_CREAT|O_APPEND, 0600);	// open logfile pointer
	if (fp){
		kernel_write(fp, data, datasize, &pos);		// write data to logfile in chunks of block size
		pos = pos + datasize; 						// increment index into log file written (global)
		filp_close(fp, NULL);						// close the logfile
		vfs_fsync(fp, 0);
	}
	return pos;
}


/** 							Hooking Functions 									**/
static asmlinkage long psi_open(const struct pt_regs *pt_regs){
	/** open(const char __user *filename, int flags,umode_t mode)
	 * Dependent registers:
     * rax: contains syscall id
     * rdi: which contains the filename 	 	= char* filename
     * rsi: which contains the flags 			= int flags
     * rdx: mode of file opening 				= int mode
     */
	// char* filename = (char*)pt_regs->di; 		z
	//int flags = (int)pt_regs->si; 		 		
	//int mode = (int) pt_regs->dx;				
	//int len = strlen(filename);
	char filename[256];
    memset(filename, 0, 256);
    filename[255] = '\0';

    long res = strncpy_from_user(filename, (const char*)pt_regs->di, 255);
    if (res != -EFAULT)
		// Log what file is being opened
		printk(KERN_INFO "[Ψo]: open(%s)", filename);

	return original_sys_open(pt_regs);
}

static asmlinkage int psi_execve(const struct pt_regs* pt_regs){
	/* execve(const char *file, const char *const argv[], const char *const envp[])
	 * Dependent registers:
     * rax: contains the syscall number 
     * rdi: holds binary file being executed/called		= char* filename
     * rsi: hold the arguments used in execve() call 	= const char* argv[]
     * rdx: holds environment variable vals for execve 	= const char* envp[]
	 */
	// char* file = (char*)pt_regs->di;
	// char* argv = (char*)pt_regs->si;
	// char* envp = (char*)pt_regs->dx;

	//TODO: Figure out how to display argv, envp. They're converting 
	// oddly from the registers, maybe shift left by 8 or something?
	// const char __user *filename = (const char*)pt_regs->di;
	char filename[256];
    memset(filename, 0, 256);
    filename[255] = '\0';

    long res = strncpy_from_user(filename, (const char*)pt_regs->di, 255);
    if (res != -EFAULT)
		// Log what file is being opened
		printk(KERN_INFO "[Ψe]: execve(%s)", filename);


	// Hand execution back to execve
	return original_execve(pt_regs);
}


static asmlinkage int psi_umask(const struct pt_regs* pt_regs){
	/** Hooked function umask(mode_t umask)
	 * Dependent Registers:
	 * * rax: holds syscall number
     * rdi: hold the umask value	= mode_t umask
	 **/
	mode_t umask = (mode_t)pt_regs->di;
	printk(KERN_NOTICE "[Ψu]: Someone changing to privs: %ld", umask);
	return original_umask(pt_regs);
}


static asmlinkage int psi_chmod(const struct pt_regs* pt_regs){
	/** Hooked function chmod(const char* f, mode_t mode)
	 *  returns 0 on success. 
	 * rax: 90 (syscall number)
	 * rdi: const char* filename
	 * rsi: mode_t mode
	 **/
	char* file = (char*)pt_regs->di;
	//mode_t mode = (mode_t)pt_regs->si;
	char filename[256];
    memset(filename, 0, 256);
    filename[255] = '\0';

    long res = strncpy_from_user(filename, (const char*)pt_regs->di, 255);
    if (res != -EFAULT)
		// Log what file is being opened
		printk(KERN_INFO "[Ψch] chmod(%s, %ld", file);
	

	return original_chmod(pt_regs);
}



static asmlinkage int psi_chown(const struct pt_regs* pt_regs){
	/** Hooked Function chown(const achar* filename, uid_t user, gid_t group)
	 * rax: 92 (syscall number)
	 * rdi: const char* file
	 * rsi: uid_t user
	 * rdx: gid_t group
	 **/
	char* file = (char*)pt_regs->di;
	uid_t user = (uid_t)pt_regs->si;
	gid_t group = (gid_t)pt_regs->dx;
	printk(KERN_INFO "[Ψch] chown(%s, %ld %ld)", file, user, group);


	return original_chown(pt_regs);
}


/* Define the hooks for ftrace hook engine */
static struct ftrace_hook intercepted[] = {
	HOOK("__x64_sys_open", psi_open, &original_sys_open),
	HOOK("__x64_sys_execve", psi_execve, &original_execve)
};


/*****************| Kernel Module Functions |*****************/


static int __init psi_start(void){
	printk(KERN_INFO "[ψ]:\t%s", "ENTANGLED");
	//Unprotect Memory and re-assign syscalls to our hooked routings 
	//cr0 = read_cr0();
	//disable_write_protection();

	// Find original system calls we want to hook
	int err;
	err = fh_install_hooks(intercepted, ARRAY_SIZE(intercepted));
    if(err) return err;

    //enable_write_protection();

	printk(KERN_INFO "[ψ]: SUCCEEDED placing syscall hooks");
	return 0;
}


static void __exit psi_stop(void){
	/* Unhook and restore the syscall and print to the kernel buffer */
	fh_remove_hooks(intercepted, ARRAY_SIZE(intercepted));
	printk(KERN_INFO "<< ψ Collapsed >>");
}


module_init(psi_start);
module_exit(psi_stop);
