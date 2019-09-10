   
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
MODULE_DESCRIPTION("modulo que intercepta e modifica o payload de um pacote udp ou tcp.");
MODULE_INFO(difficulty, "very easy");
MODULE_LICENSE("GPL");
    

static struct nf_hook_ops nfho;

struct sk_buff *socket_buffer;
struct iphdr *ip_header;
struct tcphdr *tcp_header;
struct udphdr *udp_header;

unsigned char *payload;
unsigned char *tail;

unsigned int udplen;
unsigned int tcplen;

unsigned char* it;
//unsigned int sport, dport;

char* desired_ip = "10.0.0.10";
char* dest_ip;// = (char*) kmalloc(16, sizeof(char));

char* newpayload;
unsigned int newpayload_size;
unsigned int payload_size;


unsigned int str_to_addr(char *str)
{
    unsigned int a = 0, b = 0, c = 0, d = 0, address = 0;
    sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d);
    address = (d << 24) + (c << 16) + (b << 8) + (a);
    return address;
}

void print_payload( unsigned char* p, unsigned int psize )
{
	unsigned int i = 0;
	unsigned char* aux = (unsigned char*) kmalloc(psize+1, sizeof(unsigned char));
	for(i = 0; i < psize; i++)
		aux[i] = p[i];
	pr_info("PASSOU: %s", aux);
	kfree(aux);
}

unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{

    socket_buffer = skb;
    

    if (!socket_buffer)
		return NF_ACCEPT;

    
    ip_header = (struct iphdr *)skb_network_header(socket_buffer);
    
    if (!ip_header) // pacote não possui cabecalho IP
		return NF_ACCEPT; 
        
    
    if(skb_is_nonlinear(socket_buffer))
		skb_linearize(socket_buffer);
    
    
    
	//socket_buffer->ip_summed = CHECKSUM_NONE; //stop offloading
	//socket_buffer->csum_valid = 0;
	//ip_header->check = 0;
	//ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
	
	dest_ip = (char*) kmalloc(16, sizeof(char));
	sprintf( dest_ip, "%d.%d.%d.%d", NIPQUAD(ip_header->daddr) );
	if ( strcmp( dest_ip, desired_ip ) != 0 ) return NF_ACCEPT;
	kfree(dest_ip);

	
	switch(ip_header->protocol)
	{
		case IPPROTO_UDP:
			pr_info("### UDP ###\n");
			pr_info("IP de origem: %d.%d.%d.%d\n", NIPQUAD(ip_header->saddr));
			pr_info("IP de destino: %d.%d.%d.%d\n", NIPQUAD(ip_header->daddr));
			
			udp_header = udp_hdr(socket_buffer);
			
			
			payload = (unsigned char *)((unsigned char *)udp_header + sizeof(struct udphdr));
			payload_size = ntohs(udp_header->len) - sizeof(struct udphdr);
			//payload_size = skb->len - ip_hdrlen(socket_buffer) - sizeof(struct udphdr);
			tail = skb_tail_pointer(socket_buffer);
			//payload_size = (unsigned int*)tail - (unsigned int*)payload;
			//pr_info("PAYLOAD: %s", payload);
			/*
			pr_info("PAYLOAD: ");
			for (it = payload; it != tail; ++it) {
				char c = *(char *)it;
				if (c == '\0') {
					break;
				}
				else {
					pr_info("%c", *it);
					*it = 'K';
				}
				
			}
			*/
			
			newpayload = "jonathan\n\0";
			newpayload_size = (unsigned int) strlen( newpayload );
			
			
			pr_info("AQUI1!!! skb = %d, payload = %d, newpayload = %d\n", socket_buffer->len, payload_size, newpayload_size);
			
			print_payload(payload, payload_size);
			//pr_info("PASSOU: %s\n", payload);
			/*Resize data space in buffer*/
			if(newpayload_size < payload_size){
				/*Make it smaller*/
				skb_trim(socket_buffer, socket_buffer->data_len - payload_size + newpayload_size);
				pr_info("MENOR\n");

			}else if(newpayload_size > payload_size){
				pr_info("MAIOR\n");
				int delta = newpayload_size - payload_size;
				if (delta > skb_tailroom(socket_buffer)){
					pr_info("[POLIMI] Socket Buffer too small");
					return NF_DROP;
				}
				/*Make it bigger*/
				skb_put(socket_buffer,delta);
			}
			
			/*
			udp_header = udp_hdr(socket_buffer);
			payload = (unsigned char *)((unsigned char *)udp_header + sizeof(struct udphdr));
			payload_size = ntohs(udp_header->len) - sizeof(struct udphdr);
			tail = skb_tail_pointer(socket_buffer);
			*/
			/*Copy the new payload*/
			memcpy(payload,newpayload,newpayload_size);
			print_payload( payload, newpayload_size);
			//pr_info("PASSOU: %s\n", payload);
			pr_info("AQUI2!!! skb = %d, payload = %d, newpayload = %d\n", socket_buffer->len, payload_size, newpayload_size);
				
			/*fix ip tot length*/
			ip_header->tot_len=htons(ntohs(ip_header->tot_len) - payload_size + newpayload_size);
			
			
			udp_header = udp_hdr(socket_buffer);
			socket_buffer->csum = 0;
			udplen = ntohs(udp_header->len) - payload_size + newpayload_size; //udplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
			udp_header->len = htons(udplen);
			udp_header->check = 0;
			udp_header->check = udp_v4_check(udplen,ip_header->saddr, ip_header->daddr, csum_partial((char *)udp_header, udplen, 0));
			
			pr_info("### FIM UDP ###\n");
			
		break;

		
		case IPPROTO_TCP:
		
			pr_info("### TCP ###\n");
			pr_info("IP de origem: %d.%d.%d.%d\n", NIPQUAD(ip_header->saddr));
			pr_info("IP de destino: %d.%d.%d.%d\n", NIPQUAD(ip_header->daddr));
			
			tcp_header = tcp_hdr(socket_buffer);
			payload = (unsigned char *)((unsigned char *)tcp_header + (tcp_header->doff * 4));
			payload_size = ntohs(ip_header->tot_len) - ip_hdrlen(skb) - tcp_header->doff*4;
			tail = skb_tail_pointer(socket_buffer);
			
			
			//pr_info("PAYLOAD: %s", payload);
			/*pr_info("PAYLOAD: ");
			
			for (it = payload; it != tail; ++it) {
				char c = *(char *)it;
				if (c == '\0') {
					break;
				}
				else {
					pr_info("%c", *it);
					*it = 'H';
				}
				
			}*/
			
			newpayload = "jonathan";
			newpayload_size = (unsigned int) strlen( newpayload );
			
			/*Resize data space in buffer*/
			if(newpayload_size < payload_size){
				/*Make it smaller*/
				skb_trim(socket_buffer,socket_buffer->len-payload_size+newpayload_size);

			}else if(newpayload_size > payload_size){
				int delta = newpayload_size - payload_size;
				if (delta > skb_tailroom(socket_buffer)){
					printk("[POLIMI] Socket Buffer too small");
					return NF_DROP;
				}
				/*Make it bigger*/
				skb_put(socket_buffer,delta);
			}
			/*Copy the new payload*/
			memcpy(payload,newpayload,newpayload_size);
				
			/*fix ip tot length*/
			ip_header->tot_len=htons(ntohs(ip_header->tot_len)-payload_size+newpayload_size);
			
			
			
			
			socket_buffer->csum = 0;
			tcplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
			tcp_header->check = 0;
			tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));
			
			
			pr_info("### FIM TCP ###\n");
			
		break;
	}
	
	ip_header->check = htons(0);
	ip_header->check = ip_fast_csum((unsigned char *) ip_header,ip_header->ihl);
	
	//kfree_skb (socket_buffer);
	//return 0;
	return NF_ACCEPT; // return NF_STOLEN;
}


static int __init init_main(void)
{
	nfho.hook     = hook_func; 					// ponteiro para funcao hook criada
	nfho.hooknum  = NF_INET_PRE_ROUTING; 		// a funcao hook_func executara no pre-roteamento hook do netfilter
	nfho.pf       = PF_INET; 					// pf = protocol family. Neste caso, apenas IPv4
	nfho.priority = NF_IP_PRI_FIRST; 			// informa ao netfilter que esse hook deve ser executado "primeiro"
	nf_register_net_hook(&init_net, &nfho); 	// registrando a funcao hook criada
	return 0;
}

static void __exit exit_main(void)
{
	nf_unregister_net_hook(&init_net, &nfho); 	// cancela registro da funcao hook
}

module_init(init_main);
module_exit(exit_main);

    
    
    
