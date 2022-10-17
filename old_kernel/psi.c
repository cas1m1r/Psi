/** 				ψ kernel module 			*/
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/miscdevice.h>
#include <linux/semaphore.h>
#include <linux/syscalls.h>

#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/init.h>
#include <linux/rtc.h>
#include "netfilter.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tyl3rdurd3n");
MODULE_DESCRIPTION("Using techniques from malware to find malware.");
MODULE_VERSION("0.0.2");


// Macros to enable changing the syscall table through control register
// #define DISABLE_WRITE_PROTECTION (write_cr0(read_cr0() & (~ 0x10000)))
// #define ENABLE_WRITE_PROTECTION (write_cr0(read_cr0() | 0x10000))

void**sys_call_table;

/* Function Prototypes */
static unsigned long **find_sys_call_table(void);
asmlinkage int psi_umask(mode_t umask);
asmlinkage long psi_open(const char __user *filename, int flags, umode_t mode);
asmlinkage int psi_execve(const char* file,const char* const argv[],const char* const envp[]);

asmlinkage int (*original_umask)(mode_t umask);
asmlinkage long (*original_recv)(int, void __user *, size_t, unsigned);
asmlinkage long (*original_sys_open)(const char __user *, int, umode_t);
asmlinkage int (*original_execve)(const char* file,const char* const argv[],const char* const envp[]);

/* Page Protection Functions */
static void disable_write_protection(void){
	unsigned long regval;
	asm volatile("mov %%cr0, %0":"=r"(regval));
	if (regval & 0x00010000){
		regval &= ~0x00010000;
		asm volatile("mov %0, %%cr0":
					  :"r"(regval));
	}
}

static void enable_write_protection(void){
	unsigned long regval;
	asm volatile("mov %%cr0, %0" : "=r"(regval));
	if (!(regval & 0x00010000)){
		regval |= 0x00010000;
		asm volatile("mov %0, %%cr0":
					  : "r"(regval));
	}
}

/* 			HOOKING FUNCTIONS				*/
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

asmlinkage int psi_umask(mode_t umask){
	printk(KERN_NOTICE "[Ψe]: Someone wants root");
	return original_umask(umask);
}

/* 			KERNEL MODULE FUNCTIONS			*/
static int __init psi_start(void){
	printk(KERN_INFO "[ψ]:\t%s", "ENTANGLED");
	
	// Get The Address of SYSCALL_TABLE	
	sys_call_table = (void* )kallsyms_lookup_name("sys_call_table");

    printk(KERN_INFO "[ψ]: Setting up Hooks");
	// change value in CR0 (page protection)
	disable_write_protection();
	// Place Hooks 
	original_sys_open = sys_call_table[__NR_open];
	original_execve =  sys_call_table[__NR_execve];
	original_umask =  sys_call_table[__NR_umask];
	sys_call_table[__NR_execve] = psi_execve;
	sys_call_table[__NR_umask] =  psi_umask;
	sys_call_table[__NR_open] =  psi_open;
	// Change the value back in CR0 (page protection)
	enable_write_protection();

	/* set hook option for pre routing */
	/* when pack arrived, hook_recv_fn will be triggered */
	// nfhook_recv.hook = hook_recv_fn;
	// nfhook_recv.hooknum = NF_INET_PRE_ROUTING;	// resigister pre routing hook
	// nfhook_recv.pf = PF_INET;
	// nfhook_recv.priority = 1;
	// /* check if registration is successful */
	// if (nf_register_net_hook(&init_net, &nfhook_recv)) {
	// 	printk(KERN_INFO "[Ψnx]: Could not register the netfilter receiving hook");
	// }

	// /* set hook option for post routing */
	// /* when pack is about to be sent, hook_send_fn will be triggered */
	// nfhook_send.hook = hook_send_fn;
	// nfhook_send.hooknum = NF_INET_POST_ROUTING;	// resigister porst routing hook
	// nfhook_send.pf = PF_INET;
	// nfhook_send.priority = 1;
	return 0;
}

static void __exit psi_end(void){
	printk(KERN_INFO "<< ψ Collapsed >>");
	printk(KERN_INFO "[ψ]>: Releasing Hooks");
	/* Restore original values in syscall table */
    disable_write_protection();
	sys_call_table[__NR_open] = original_sys_open;
	sys_call_table[__NR_execve] = original_execve;
	sys_call_table[__NR_umask] = original_umask;
	enable_write_protection();
}

// unsigned int hook_recv_fn(void *priv,
// 		struct sk_buff *skb,
// 		const struct nf_hook_state *state){
	
// 	/* declaration */
// 	unsigned short dest_port;

// 	/* hard coding for demo purpose */
// 	/* get ip header from socket buffer we are owned */
// 	ip_header = ip_hdr(skb);
// 	char IP[16];
// 	snprintf(IP,16,"%pI4",&ip_header->saddr);

// 	/* get different header for different protocol  */
// 	switch (ip_header->protocol) {
// 		/* TCP */
// 		case IPPROTO_TCP:
// 			/* get tcp header if the protocol of the pack is tcp */
// 			tcp_header = tcp_hdr(skb);
// 			/* translate from network bits order to host bits order */
// 			dest_port = ntohs(tcp_header->dest);
		
// 			if (!strstr(IP,"10.23.")){
// 				/* print out the information in the header */
// 				printk(KERN_INFO "[Ψnx]: Packet received from: %pI4:%d",&(ip_header->saddr), dest_port);
// 				break;
// 			}

// 		/* UDP */
// 		case IPPROTO_UDP:
// 			/* get udp header if the protocol of the pack is udp */
// 			udp_header = udp_hdr(skb);
// 			/* translate from network bits order to host bits order */
// 			dest_port = ntohs(udp_header->dest);
// 			if (!strstr(IP,"10.23.")){
// 				/* print out the information in the header */
// 				printk(KERN_INFO "[Ψnx]: Packet received from: %pI4:%d",&(ip_header->saddr),dest_port);
// 				break;
// 			}

// 		/* Other protocol like ICMP, RAW, ESP, etc. */
// 		default:
// 			// printk(KERN_INFO "[Ψnx]: Packet received from: %pI4\n", &(ip_header->saddr));
// 			break;
// 	}
// 	/* let netfilter accept the incoming pack */
// 	return NF_ACCEPT;
// }

// unsigned int hook_send_fn(void *priv, 
// 		struct sk_buff *skb, 
// 		const struct nf_hook_state *state) {
	
// 	/* declaration */
// 	unsigned short dest_port;

// 	/* hard coding for demo purpose */
// 	/* get ip header from socket buffer we are owned */
// 	ip_header = ip_hdr(skb);

// 	char IP[16];
// 	snprintf(IP,16,"%pI4",&ip_header->saddr);

// 	/* get different header for different protocol  */
// 	switch (ip_header->protocol) {
// 		/* TCP */
// 		case IPPROTO_TCP:
// 			/* get tcp header if the protocol of the pack is tcp */
// 			tcp_header = tcp_hdr(skb);
// 			/* translate from network bits order to host bits order */
// 			dest_port = ntohs(tcp_header->dest);

// 			/* drop the pack if it should be blocked */
// 			if (!strstr(IP,"10.23.")){
// 				/* print out the information in the header */
// 				printk(KERN_INFO "[Ψnx]: Packet sent to: %pI4:%d",&(ip_header->saddr), dest_port);
// 				break;
// 			}
// 		/* UDP */
// 		case IPPROTO_UDP:
// 			/* get udp header if the protocol of the pack is udp */
// 			udp_header = udp_hdr(skb);
// 			/* translate from network bits order to host bits order */
// 			dest_port = ntohs(udp_header->dest);

// 			/* drop the pack if it should be blocked */
// 			if (!strstr(IP,"10.23.")){
// 				/* print out the information in the header */
// 				printk(KERN_INFO "[Ψnx]: Packet sent to: %pI4:%d",&(ip_header->daddr), dest_port);
// 				break;
// 			}

// 		/* Other protocol like ICMP, RAW, ESP, etc. */
// 		default:
// 			// printk(KERN_INFO "[Ψnx]: Packet sent to %pI4\n", &(ip_header->saddr));
// 			break;
// 	}
// 	/* let netfilter accept the incoming pack */
// 	return NF_ACCEPT;
// }

module_init(psi_start);
module_exit(psi_end);
