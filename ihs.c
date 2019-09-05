   
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
    
MODULE_AUTHOR("Carolina e Jonathan");
MODULE_DESCRIPTION("net driver module to collect statistics");
MODULE_INFO(difficulty, "very easy");
MODULE_LICENSE("GPL");
    
    
struct packet_type pckt_proto;
    
int pckt_rcv (struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    //mdelay(5000);
    printk(KERN_INFO "INICIO!\n");
    





    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    struct list_head *p;
    unsigned char* __data__ = NULL;

    unsigned int src_ip = (unsigned int)ip_header->saddr;
    unsigned int dest_ip = (unsigned int)ip_header->daddr;
    unsigned int src_port = 0;
    unsigned int dest_port = 0;

    if (ip_header->protocol==17) {
            pr_info("UDP\n");
            udp_header = (struct udphdr *)skb_transport_header(skb);
            src_port = (unsigned int)ntohs(udp_header->source);
    } else if (ip_header->protocol == 6) {
            pr_info("TCP\n");
            tcp_header = (struct tcphdr *)skb_transport_header(skb);
            src_port = (unsigned int)ntohs(tcp_header->source);
            dest_port = (unsigned int)ntohs(tcp_header->dest);
            __data__ = (unsigned char *)((unsigned char *)tcp_header + (tcp_header->doff)*4);
    }

    printk(KERN_INFO "OUT packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %u\n", src_ip, src_port, dest_ip, dest_port, ip_header->protocol);
    printk(KERN_DEBUG "IP addres = %pI4  DEST = %pI4\n", &src_ip, &dest_ip);
    pr_info("DATA: %s\n", __data__);





    
    kfree_skb (skb);
    return 0;
}
    
static int __init pckt_init(void)
{
    
    pckt_proto.type = htons(ETH_P_IP);
    pckt_proto.dev = dev_get_by_name (&init_net, "enp0s3");
    pckt_proto.func = pckt_rcv;
    
    dev_add_pack (&pckt_proto);
    
    printk(KERN_INFO "MODULO INSERIDO!\n");
    return 0; // Non-zero return means that the module couldn't be loaded.
}
    
static void __exit pckt_cleanup(void)
{
    dev_remove_pack(&pckt_proto);
    printk(KERN_INFO "FIM!\n");
}
   
module_init(pckt_init);
module_exit(pckt_cleanup);


    
    
    
