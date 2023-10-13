/** 				ψ kernel module 			**/
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/fs.h>
#include "netfilter.h"
#include "hooks.h"

// Module Defs 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("tyl3rdurd3n");
MODULE_DESCRIPTION("Using malware to find malware.");
MODULE_VERSION("0.3");

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
	char* filename = (char*)pt_regs->di; 		
	int flags = (int)pt_regs->si; 		 		
	int mode = (int) pt_regs->dx;				
	int len = strlen(filename);
	// Log what file is being opened
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
	char* envp = (char*)pt_regs->dx;

	//TODO: Figure out how to display argv, envp. They're converting 
	// oddly from the registers, maybe shift left by 8 or something?

	printk(KERN_INFO "[ψe]: %s %pS", file, argv);


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
	mode_t mode = (mode_t)pt_regs->si;

	printk(KERN_INFO "[Ψch] chmod(%s, %ld", file, mode);

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

/*****************| Kernel Module Functions |*****************/


static int __init psi_start(void){
	printk(KERN_INFO "[ψ]:\t%s", "ENTANGLED");
	
	// find syscall table 
	sys_call_table = hook_syscall_table();
	
	// check whether we found it, if not just stop because everything else will fail 
	if (sys_call_table == NULL) return -1;
	printk(KERN_INFO "[ψ]: Found sys_call_table at: 0x%p\n", sys_call_table);	
	
	BLK_CNT = 0;
	char* msg = (char*)kmalloc(sizeof(char)*BLK_SZ, GFP_USER);
	snprintf(msg,BLK_SZ,"[ψ]: Found sys_call_table at: 0x%p\n", sys_call_table);
	BLK_CNT = psi_print(msg, BLK_SZ, BLK_CNT);
	kfree(msg);

	// Unprotect Memory and re-assign syscalls to our hooked routings 
	cr0 = read_cr0();
	disable_write_protection();

	// Find original system calls we want to hook
	printk(KERN_INFO "[ψ]: Replacing Syscall with Hooks...");
	original_sys_open = (tt_syscall) sys_call_table[__NR_open];
	original_execve =  (tt_syscall) sys_call_table[__NR_execve];
	original_umask =  (tt_syscall) sys_call_table[__NR_umask];
	original_chmod = (tt_syscall) sys_call_table[__NR_chmod];
	original_chown = (tt_syscall) sys_call_table[__NR_chown];
	

	// replace original system calls with our hooked version 
	sys_call_table[__NR_execve] = psi_execve;
	sys_call_table[__NR_umask] =  psi_umask;
	sys_call_table[__NR_open] =  psi_open;
	sys_call_table[__NR_chmod] = psi_chmod;
	sys_call_table[__NR_chown] = psi_chown;

	// reset write protection flag!
	enable_write_protection();
	printk(KERN_INFO "[ψ]: SUCCEEDED placing syscall hooks");
	printk(KERN_INFO "[ψ]: Attempting to hook socket functions...");
	/* set hook option for pre routing */
	/* when pack arrived, hook_recv_fn will be triggered */
	nfhook_recv.hook = hook_recv_fn;
	nfhook_recv.hooknum = NF_INET_PRE_ROUTING;	// resigister pre routing hook
	nfhook_recv.pf = PF_INET;
	nfhook_recv.priority = 1;
	/* check if registration is successful */
	if (nf_register_net_hook(&init_net, &nfhook_recv)) {
		printk(KERN_INFO "[Ψnx]: Could not register the netfilter receiving hook");
	}
	printk(KERN_INFO "[Ψnx]: Hooks Set for all inbound network traffic");
	/* set hook option for post routing */
	/* when pack is about to be sent, hook_send_fn will be triggered */
	nfhook_send.hook = hook_send_fn;
	nfhook_send.hooknum = NF_INET_POST_ROUTING;	// resigister porst routing hook
	nfhook_send.pf = PF_INET;
	nfhook_send.priority = 1;
	if (nf_register_net_hook(&init_net, &nfhook_send)) {
		printk(KERN_INFO "[Ψnx]: Could not register the netfilter receiving hook");
	}
	printk(KERN_INFO "[Ψnx]: Hooks Set for all outbound network traffic");

	char* msg2 = (char*)kmalloc(sizeof(char)*BLK_SZ, GFP_USER);
	snprintf(msg2,BLK_SZ,"[ψ]: All Socket and System hooks are set.\n");
	BLK_CNT = psi_print(msg2, BLK_SZ, BLK_CNT);
	kfree(msg2);
	return 0;
}

unsigned int hook_recv_fn(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state){
	
	/* declaration */
	unsigned short dest_port;

	/* hard coding for demo purpose */
	/* get ip header from socket buffer we are owned */
	ip_header = ip_hdr(skb);
	char IP[16];
	snprintf(IP,16,"%pI4",&ip_header->saddr);

	/* get different header for different protocol  */
	switch (ip_header->protocol) {
		/* TCP */
		case IPPROTO_TCP:
			/* get tcp header if the protocol of the pack is tcp */
			tcp_header = tcp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(tcp_header->dest);
		
			if (!strstr(IP,"10.0.") && !strstr(IP,"127.0.") && !strstr(IP,"192.168.")){
				/* print out the information in the header */
				printk(KERN_INFO "[Ψnx]: Packet received from: %pI4:%d",&(ip_header->saddr), dest_port);
				
				// Log event
				// char* msg = (char*)kmalloc(sizeof(char)*BLK_SZ, GFP_USER);
				// snprintf(msg,BLK_SZ,"[Ψnx]: Packet received from: %pI4:%d\n",&(ip_header->saddr), dest_port);
				// BLK_CNT = psi_print(msg, BLK_SZ,BLK_CNT);
				// kfree(msg);
				break;
			}

		/* UDP */
		case IPPROTO_UDP:
			/* get udp header if the protocol of the pack is udp */
			udp_header = udp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(udp_header->dest);
			if (!strstr(IP,"10.0.") && !strstr(IP,"127.0.") && !strstr(IP,"192.168.")){
				/* print out the information in the header */
				printk(KERN_INFO "[Ψnx]: Packet received from: %pI4:%d",&(ip_header->saddr),dest_port);
				
				// Log event
				// char* msg = (char*)kmalloc(sizeof(char)*BLK_SZ, GFP_USER);
				// snprintf(msg,BLK_SZ,"[Ψnx]: Packet received from: %pI4:%d\n",&(ip_header->saddr), dest_port);
				// BLK_CNT = psi_print(msg, BLK_SZ,BLK_CNT);
				// kfree(msg);
				break;
			}

		/* Other protocol like ICMP, RAW, ESP, etc. */
		default:
			// printk(KERN_INFO "[Ψnx]: Packet received from: %pI4\n", &(ip_header->saddr));
			break;
	}
	/* let netfilter accept the incoming pack */
	return NF_ACCEPT;
}

unsigned int hook_send_fn(void *priv, 
		struct sk_buff *skb, 
		const struct nf_hook_state *state) {
	
	/* declaration */
	unsigned short dest_port;

	/* hard coding for demo purpose */
	/* get ip header from socket buffer we are owned */
	ip_header = ip_hdr(skb);

	char IP[16];
	snprintf(IP,16,"%pI4",&ip_header->saddr);

	/* get different header for different protocol  */
	switch (ip_header->protocol) {
		/* TCP */
		case IPPROTO_TCP:
			/* get tcp header if the protocol of the pack is tcp */
			tcp_header = tcp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(tcp_header->dest);

			/* drop the pack if it should be blocked */
			if (!strstr(IP,"10.0.") && !strstr(IP,"127.0.")&& !strstr(IP,"192.168.")){
				/* print out the information in the header */
				printk(KERN_INFO "[Ψnx]: Packet sent to: %pI4:%d",&(ip_header->saddr), dest_port);
				break;
			}
		/* UDP */
		case IPPROTO_UDP:
			/* get udp header if the protocol of the pack is udp */
			udp_header = udp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(udp_header->dest);

			/* drop the pack if it should be blocked */
			if (!strstr(IP,"10.0.") && !strstr(IP,"127.0.")&& !strstr(IP,"192.168.")){
				/* print out the information in the header */
				printk(KERN_INFO "[Ψnx]: Packet sent to: %pI4:%d",&(ip_header->daddr), dest_port);
				break;
			}

		/* Other protocol like ICMP, RAW, ESP, etc. */
		default:
			// printk(KERN_INFO "[Ψnx]: Packet sent to %pI4\n", &(ip_header->saddr));
			break;
	}
	/* let netfilter accept the incoming pack */
	return NF_ACCEPT;
}

static void __exit psi_stop(void){
	disable_write_protection();
	// fix syscall table 
	sys_call_table[__NR_open] = original_sys_open;
	sys_call_table[__NR_execve] = original_execve;
	sys_call_table[__NR_umask] = original_umask;
	enable_write_protection(); 
	nf_unregister_net_hook(&init_net, &nfhook_recv);
	nf_unregister_net_hook(&init_net, &nfhook_send);
	printk(KERN_INFO "<< ψ Collapsed >>");
	BLK_CNT = psi_print("[ψ]>: Releasing Hooks\n", 23, BLK_CNT);
}


module_init(psi_start);
module_exit(psi_stop);
