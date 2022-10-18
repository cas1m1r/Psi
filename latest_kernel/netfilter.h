#include <linux/kernel.h>		// included for printk
#include <linux/module.h>		// required for all the LKM
#include <linux/init.h>			// included for __init and __exit
#include <linux/netfilter.h>	// included for netfilter functionality
#include <linux/ip.h>			// included for ip_hdr
#include <linux/tcp.h>			// included for tcp_hdr
#include <linux/udp.h>			// included for udp_hdr
#include <linux/types.h>		// included for typing less words
#include <linux/inet.h>			// included for in_aton
#include <linux/moduleparam.h>	// included for module_param

/*********************************************/
/* declaration of varibles and functions below */
/*********************************************/

/* hook options stuct for both receiving and sending */
struct nf_hook_ops nfhook_recv;
struct nf_hook_ops nfhook_send;

/* differnet types of headers for different layers and protocols */
struct iphdr *ip_header;
struct udphdr *udp_header;
struct tcphdr *tcp_header;


/**
 * Check if the pack should be accepted or dropped according to the result 
 * checked by the function is_blocked. This function that will be 
 * triggered when pack arrived.
 * 
 * @priv: a pointer to the privilge of the hook triggered? Not clear, not used 
 * 			in this module
 * @skb: a pointer to the network packet buffer
 * @state: a pointer to the struct contains the state information of the hook
 * 	       	triggered
 *
 * Return NF_ACCEPT if the pack in @skb should not be blocked and NF_DROP if 
 * it should be, which allows netfilter to accept the pack or drop the pack.
 */
unsigned int hook_recv_fn(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state);

/**
 * Check if the pack should be accepted or dropped according to the result 
 * checked by the function is_blocked. This function that will be 
 * triggered when pack is about to be sent.
 *
 * @priv: a pointer to the privilge of the hook triggered? Not clear, not used 
 * 			in this module
 * @skb: a pointer to the network packet buffer
 * @state: a pointer to the struct contains the state information of the hook
 * 	       	triggered
 *
 * Return NF_ACCEPT if the pack in @skb should not be blocked and NF_DROP if 
 * it should be, which allows netfileter to accept the pack or drop it.
 */
unsigned int hook_send_fn(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state);

