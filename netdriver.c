   
#include <linux/module.h> // included for all kernel modules
#include <linux/kernel.h> // included for KERN_INFO
#include <linux/init.h> // included for __init and __exit macros
#include <linux/skbuff.h> // included for struct sk_buff
#include <linux/if_packet.h> // include for packet info
#include <linux/ip.h> // include for ip_hdr 
#include <linux/netdevice.h> // include for dev_add/remove_pack
#include <linux/if_ether.h> // include for ETH_P_ALL
#include <linux/delay.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
//#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

//#define INET_ADDRSTRLEN 16

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]


MODULE_AUTHOR("Carolina e Jonathan");
MODULE_DESCRIPTION("net driver module to intercept and modify a packet");
MODULE_INFO(difficulty, "very easy");
MODULE_LICENSE("GPL");
    

static struct nf_hook_ops nfho;
struct iphdr *iph;
struct tcphdr *tcp_header;
struct udphdr *udp_header;
struct sk_buff *sock_buff;
unsigned int sport, dport;
unsigned char *user_data;
unsigned char *tail;



unsigned int str_to_addr(char *str)
{
    unsigned int a = 0, b = 0, c = 0, d = 0, address = 0;
    sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d);
    address = (d << 24) + (c << 16) + (b << 8) + (a);
    return address;
}


//nfho is a nf_hook_ops struct. This struct stores all the
//required information to register a Netfilter hook.

//hook_func is our Netfilter function that will be called at the pre-routing
//hook. This hook merely logs that Netfilter received a packet and tells
//Netfilter to continue processing that packet.
unsigned int hook_func(void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state)
{
       //NOTE: Feel free to uncomment printks! If you are using Vagrant and SSH
     //      too many printk's will flood your logs.
    //printk(KERN_INFO "=== BEGIN HOOK ===\n");

    sock_buff = skb;
    

    if (!sock_buff) {
        return NF_ACCEPT;
    }

    iph = (struct iphdr *)skb_network_header(sock_buff);

	

    if (!iph) {
        //printk(KERN_INFO "no ip header\n");
        return NF_ACCEPT;
    }
    
    if(skb_is_nonlinear(sock_buff))
      skb_linearize(sock_buff);
    
	sock_buff->ip_summed = CHECKSUM_NONE; //stop offloading
	sock_buff->csum_valid = 0;
	iph->check = 0;
	iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
	
	if(iph->protocol==IPPROTO_UDP) {
        //return NF_ACCEPT;
        printk(KERN_INFO "=== BEGIN UDP ===\n");
        printk(KERN_INFO "IP header: original destin: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));
        //iph->daddr = str_to_addr("10.0.0.10");
        printk(KERN_INFO "IP header: modified destin: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));
        printk(KERN_INFO "IP header: original source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
        //printk(KERN_INFO "=== END UDP ===\n");
        
        udp_header = udp_hdr(sock_buff);
        unsigned int udplen;
        
		
		
		
		user_data = (unsigned char *)((unsigned char *)udp_header + sizeof(struct udphdr));
        tail = skb_tail_pointer(sock_buff);
        //pr_info("DATA: %s", user_data);
        pr_info("DATA: ");
        unsigned char* it;
		for (it = user_data; it != tail; ++it) {
			char c = *(char *)it;
			if (c == '\0') {
				break;
			}
			else {
				pr_info("%c", *it);
				*it = 'K';
			}
			
		}
		
		sock_buff->csum =0;
		udplen = ntohs(iph->tot_len) - iph->ihl*4;
		udp_header->check = 0;
		udp_header->check = udp_v4_check(udplen,iph->saddr, iph->daddr,csum_partial((char *)udp_header, udplen, 0));
		
        printk(KERN_INFO "=== END UDP ===\n");


    }

    if(iph->protocol==IPPROTO_TCP) {
        //return NF_ACCEPT;
        printk(KERN_INFO "=== BEGIN TCP ===\n");
        printk(KERN_INFO "IP header: original destin: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));
        //iph->daddr = str_to_addr("10.0.0.10");
        printk(KERN_INFO "IP header: modified destin: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));
        printk(KERN_INFO "IP header: original source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
        //printk(KERN_INFO "=== END TCP ===\n");
        
        
        tcp_header = tcp_hdr(sock_buff);
        user_data = (unsigned char *)((unsigned char *)tcp_header + (tcp_header->doff * 4));
        tail = skb_tail_pointer(sock_buff);
        //pr_info("DATA: %s", user_data);
        pr_info("DATA: ");
        unsigned char* it;
		for (it = user_data; it != tail; ++it) {
			char c = *(char *)it;
			if (c == '\0') {
				break;
			}
			else {
				//*it = 'h';
				pr_info("%c", *it);
			}
			
		}
		//pr_info("\n");
        
        
        //unsigned int tcplen;
        //sport = htons((unsigned short int) tcp_header->source);
        //dport = htons((unsigned short int) tcp_header->dest);
        //printk(KERN_INFO "TCP ports: source: %d, dest: %d \n", sport, dport);
        //printk(KERN_INFO "SKBuffer: len %d, data_len %d\n", sock_buff->len, sock_buff->data_len);
		
		//sock_buff->csum =0;
		//tcplen = ntohs(iph->tot_len) - iph->ihl*4;
		//tcp_header->check = 0;
		//tcp_header->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial((char *)tcp_header, tcplen, 0));
		
		
		printk(KERN_INFO "=== END TCP ===\n");
    }

    if(iph->protocol==IPPROTO_ICMP) {
        printk(KERN_INFO "=== BEGIN ICMP ===\n");
        printk(KERN_INFO "IP header: original source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
        //iph->saddr = iph->saddr ^ 0x10000000;
        //iph->saddr = str_to_addr("10.0.0.10");
        printk(KERN_INFO "IP header: modified source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
        printk(KERN_INFO "IP header: original destin: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));
        printk(KERN_INFO "=== END ICMP ===\n");

    }

    //if(in) { printk(KERN_INFO "in->name:  %s\n", in->name); }
    //if(out) { printk(KERN_INFO "out->name: %s\n", out->name); }
    //printk(KERN_INFO "=== END HOOK ===\n");
    
	//struct sk_buff* skbc = skb_copy(skb, GFP_ATOMIC);
	
	//skb_tx_timestamp(sock_buff);
	//sock_buff->ip_summed = CHECKSUM_UNNECESSARY;
	
	ip_send_check(iph);
	//return 0;
	// return NF_STOLEN;
	return NF_ACCEPT; 
}

//initialize will setup our Netfilter hook when our kernel
//module is loaded.
static int __init initialize(void) {
        nfho.hook     = hook_func; //Points to our hook function.
        nfho.hooknum  = NF_INET_PRE_ROUTING; //Our function will run at Netfilter's pre-routing hook.
        nfho.pf       = PF_INET; //pf = protocol family. We are only interested in IPv4 traffic.
        nfho.priority = NF_IP_PRI_FIRST; //Tells Netfilter this hook should be ran "first" (there is of-course, more to this when other hooks have this priority)
        nf_register_net_hook(&init_net, &nfho); //We now register our hook function.
        return 0;
}

static void __exit cleanup(void) {
        nf_unregister_net_hook(&init_net, &nfho); //unregister our hook
}

module_init(initialize);
module_exit(cleanup);

    
    
    
