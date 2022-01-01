/** 				ψ kernel module 			*/
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include <linux/semaphore.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/cdev.h>o
#include <linux/init.h>
#include <linux/rtc.h>
#include "nmonitor.h"
int unlocked = 0;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tyl3rdurd3n");
MODULE_DESCRIPTION("Using techniques from malware to find malware.");
MODULE_VERSION("0.0.1");


// Macros to enable changing the syscall table through control register
#define DISABLE_WRITE_PROTECTION (write_cr0(read_cr0() & (~ 0x10000)))
#define ENABLE_WRITE_PROTECTION (write_cr0(read_cr0() | 0x10000))

asmlinkage unsigned long **sys_call_table;

/* Function Prototypes */
static unsigned long **find_sys_call_table(void);
asmlinkage int psi_umask(mode_t umask);
asmlinkage long psi_open(const char __user *filename, int flags, umode_t mode);
asmlinkage int psi_execve(const char* file,const char* const argv[],const char* const envp[]);
asmlinkage int (*original_umask)(mode_t umask);
asmlinkage long (*original_sys_open)(const char __user *, int, umode_t);
asmlinkage int (*original_execve)(const char* file,const char* const argv[],const char* const envp[]);
asmlinkage long (*original_bind)(int, struct sockaddr __user *, int);
unsigned int hook_recv_fn(void *,struct sk_buff *,const struct nf_hook_state *);
asmlinkage long (*original_recv)(int, void __user *, size_t, unsigned);





/* 			HOOKING FUNCTIONS				*/
static unsigned long **find_sys_call_table() {
    unsigned long offset;
    unsigned long **sct;

    for(offset=PAGE_OFFSET; offset<ULLONG_MAX; offset+=sizeof(void *)) {
	sct = (unsigned long **) offset;
	if(sct[__NR_close] == (unsigned long *) sys_close)
	    return sct;
    }
    return NULL;
}

void create_logfile(void){
	char *argv[] = { "/usr/bin/touch", "/tmp/activity.psilog",NULL };
    char *envp[] = { "HOME=/", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}


asmlinkage long psi_open(const char __user *filename, int flags,umode_t mode){
	int len = strlen(filename);
	// Log go output device what file is being opened
	printk("[Ψo]: open(%s)", filename);
	return (*original_sys_open)(filename, flags, mode);
}

asmlinkage int psi_execve(const char *file, const char *const argv[], const char *const envp[]){
	
	int nargin = sizeof(argv)/sizeof(const char);
	if(nargin > 1){
		printk(KERN_INFO "[ψe]: %s %s", argv[0], argv[1]);
	}
	
	// Hand execution back to execve
	return original_execve(file, argv, envp);
}

asmlinkage long psi_bind(int fd,struct sockaddr __user *s, int flag){
	// if(s->sa_family == AF_INET){
	// 	 &(((struct sockaddr_in*)s)->sin_addr);
	// }
	printk(KERN_INFO "[Ψs]: socket bind('0.0.0.0',%d)",port);
	return original_bind(fd, s, flag);
}




// Should hook the setuid function to always work for username psi
asmlinkage int psi_umask(mode_t umask){
	printk(KERN_NOTICE "[Ψe]: Someone wants root");
	return original_umask(umask);
}

/* 			KERNEL MODULE FUNCTIONS			*/
static int __init psi_start(void){
	printk(KERN_INFO "[ψ]:\t%s", "ENTANGLED");
	
	// Get The Address of SYSCALL_TABLE	
	sys_call_table = find_sys_call_table();
    if(!sys_call_table) { /* operation not permitted */
		printk(KERN_ERR "[Ψ]: Couldn't find sys_call_table.\n");
		return -EPERM;  
    }

    printk(KERN_INFO "[ψ]: Setting up Hooks");
	// change value in CR0
	DISABLE_WRITE_PROTECTION;
	// Place Hooks 
	// original_sys_open = (void *) sys_call_table[__NR_open];
	original_execve = (void *) sys_call_table[__NR_execve];
	original_umask = (void *) sys_call_table[__NR_umask];
	// original_bind = (void *) sys_call_table[__NR_bind];
	sys_call_table[__NR_execve] = (unsigned long*) psi_execve;
	sys_call_table[__NR_umask] = (unsigned long*) psi_umask;
	// sys_call_table[__NR_open] = (unsigned long*) psi_open;
	// sys_call_table[__NR_bind] = (unsigned long*) psi_bind;
	// Change the value back in CR0
	ENABLE_WRITE_PROTECTION;

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

	/* set hook option for post routing */
	/* when pack is about to be sent, hook_send_fn will be triggered */
	nfhook_send.hook = hook_send_fn;
	nfhook_send.hooknum = NF_INET_POST_ROUTING;	// resigister porst routing hook
	nfhook_send.pf = PF_INET;
	nfhook_send.priority = 1;
	return 0;
}


static void __exit psi_end(void){
	printk(KERN_INFO "<< ψ Collapsed >>");
	printk(KERN_INFO "[ψ]>: Releasing Hooks");
	/* Restore original values in syscall table */
    DISABLE_WRITE_PROTECTION;
	// sys_call_table[__NR_open] = (unsigned long *) original_sys_open;
	sys_call_table[__NR_execve] = (unsigned long *) original_execve;
	sys_call_table[__NR_umask] = (unsigned long *) original_umask;
	// sys_call_table[__NR_bind] = (unsigned long *) original_bind;
	ENABLE_WRITE_PROTECTION;
}

unsigned int hook_recv_fn(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state){
	
	/* declaration */
	unsigned short dest_port;

	/* hard coding for demo purpose */
	/* get ip header from socket buffer we are owned */
	ip_header = ip_hdr(skb);

	/* get different header for different protocol  */
	switch (ip_header->protocol) {
		/* TCP */
		case IPPROTO_TCP:
			/* get tcp header if the protocol of the pack is tcp */
			tcp_header = tcp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(tcp_header->dest);
	
			
			/* print out the information in the header */
			printk(KERN_INFO "[Ψnx]: Packet received from: %pI4:%d",&(ip_header->saddr), dest_port);
			break;

		/* UDP */
		case IPPROTO_UDP:
			/* get udp header if the protocol of the pack is udp */
			udp_header = udp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(udp_header->dest);

			/* print out the information in the header */
			printk(KERN_INFO "[Ψnx]: Packet received from: %pI4:%d",&(ip_header->saddr),dest_port);
			break;

		/* Other protocol like ICMP, RAW, ESP, etc. */
		default:
			printk(KERN_INFO "[Ψnx]: Packet received from: %pI4\n", &(ip_header->saddr));
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

	/* get different header for different protocol  */
	switch (ip_header->protocol) {
		/* TCP */
		case IPPROTO_TCP:
			/* get tcp header if the protocol of the pack is tcp */
			tcp_header = tcp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(tcp_header->dest);

			/* drop the pack if it should be blocked */
			

			/* print out the information in the header */
			printk(KERN_INFO "[Ψnx]: Packet sent to: %pI4:%d",&(ip_header->saddr), dest_port);
			break;

		/* UDP */
		case IPPROTO_UDP:
			/* get udp header if the protocol of the pack is udp */
			udp_header = udp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(udp_header->dest);

			/* drop the pack if it should be blocked */
			

			/* print out the information in the header */
			printk(KERN_INFO "[Ψnx]: Packet sent to: %pI4:%d",&(ip_header->daddr), dest_port);
			break;

		/* Other protocol like ICMP, RAW, ESP, etc. */
		default:
			printk(KERN_INFO "[Ψnx]: Packet sent to %pI4\n", &(ip_header->saddr));
			break;
	}
	/* let netfilter accept the incoming pack */
	return NF_ACCEPT;
}

module_init(psi_start);
module_exit(psi_end);


/************
 * N O T E S
 * 
 * Setting up a /dev/psi works pretty well, but piping messages out
 * through that instead of to DMESG is turning out to be a bit hard
 * to get working right.
 * 
 * 
 * And this isnt really all that useful to users if they need to be
 * continuously polling dmesg to see data. It's also probably bad 
 * practice to congest the dmesg log like that in the first place.
 * 
 * In the end a seperate file seems clean, but then we have to essentially hijack 
 * all file operations to make sure they dont interfere with our logs... So 
 * basically employing techniques from malware to make a tool that could hopefully
 * make finding malware easier.
 ************/