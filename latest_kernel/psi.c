/** 				ψ kernel module 			**/
#include <linux/module.h>
#include <linux/init.h>
#include "hooks.h"

// Module Defs 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("tyl3rdurd3n");
MODULE_DESCRIPTION("Using malware to find malware.");
MODULE_VERSION("0.3");

/* Function Prototypes */
static int 		__init psi_start(void);
static void 	__exit psi_stop(void);

// custom types for holding original syscalls (taken from reveng_rtkit)
typedef asmlinkage long(*tt_syscall)(const struct pt_regs*);
static tt_syscall original_sys_open;
static tt_syscall original_execve;
static tt_syscall original_umask;


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

/** 							Hooking Functions 									**/
static asmlinkage long psi_open(const struct pt_regs *pt_regs){
	/** open(const char __user *filename, int flags,umode_t mode)
	 * Dependent registers:
     * rax: contains syscall id
     * rdi: which contains the filename 	 	= char* filename
     * rsi: which contains the flags 			= int flags
     * rdx: mode of file opening 				= int mode
     */
	char* filename = (char*)pt_regs->di; 		
	int flags = (int)pt_regs->si; 		 		
	int mode = (int) pt_regs->dx;				
	int len = strlen(filename);
	// Log go output device what file is being opened
	printk("[Ψo]: open(%s, %d, %d)", filename, flags, mode);
	return (*original_sys_open)(pt_regs);
}

static asmlinkage int psi_execve(const struct pt_regs* pt_regs){
	/* execve(const char *file, const char *const argv[], const char *const envp[])
	 * Dependent registers:
     * rax: contains the syscall number 
     * rdi: holds binary file being executed/called		= char* filename
     * rsi: hold the arguments used in execve() call 	= const char* argv[]
     * rdx: holds environment variable vals for execve 	= const char* envp[]
	 */
	char* file = (char*)pt_regs->di;
	char* argv = (char*)pt_regs->si;
	// char* envp[] = (char*)pt_regs->dx;

	printk(KERN_INFO "[ψe]: %s %p", file, argv);
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
	printk(KERN_NOTICE "[Ψe]: Someone wants root");
	return original_umask(pt_regs);
}

/*****************| Kernel Module Functions |*****************/
static int __init psi_start(void){
	printk(KERN_INFO "[ψ]:\t%s", "ENTANGLED");
	
	// find syscall table 
	sys_call_table = hook_syscall_table();
	
	// check whether we found it, if not just stop because everything else will fail 
	if (sys_call_table == NULL) return -1;
	printk(KERN_INFO "[ψ]: Found sys_call_table at: 0x%p\n", sys_call_table);	

	// Unprotect Memory and re-assign syscalls to our hooked routings 
	cr0 = read_cr0();
	disable_write_protection();

	// Place Hooks 
	printk(KERN_INFO "[ψ]: Setting up Hooks");
	original_sys_open = (tt_syscall) sys_call_table[__NR_open];
	original_execve =  (tt_syscall) sys_call_table[__NR_execve];
	original_umask =  (tt_syscall) sys_call_table[__NR_umask];
	
	sys_call_table[__NR_execve] = psi_execve;
	sys_call_table[__NR_umask] =  psi_umask;
	sys_call_table[__NR_open] =  psi_open;

	// reset write protection flag!
	enable_write_protection();
	printk(KERN_INFO "[ψ]: SUCCEEDED placing syscall hooks");
	return 0;
}


static void __exit psi_stop(void){
	printk(KERN_INFO "[ψ]>: Releasing Hooks");
	disable_write_protection();
	// fix syscall table 
	sys_call_table[__NR_open] = original_sys_open;
	sys_call_table[__NR_execve] = original_execve;
	sys_call_table[__NR_umask] = original_umask;
	enable_write_protection(); 
	printk(KERN_INFO "<< ψ Collapsed >>");
}


module_init(psi_start);
module_exit(psi_stop);
