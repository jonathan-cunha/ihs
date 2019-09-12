#include <linux/netfilter_ipv4.h>
#include <net/tcp.h>
#include <net/udp.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]


MODULE_AUTHOR("Carolina Santana Louzada");
MODULE_AUTHOR("Jonathan Santos Cunha");
MODULE_DESCRIPTION("Modulo que interceptador e modificador de payload de pacotes udp e tcp.");
MODULE_INFO(difficulty, "very easy");
MODULE_LICENSE("GPL");
    

static struct nf_hook_ops nfho;

struct sk_buff *socket_buffer;
unsigned char *tail;

struct iphdr *ip_header;
struct tcphdr *tcp_header;
struct udphdr *udp_header;
unsigned int udplen;
unsigned int tcplen;

unsigned char *payload;
unsigned int payload_len;
char* new_payload;
unsigned int new_payload_len;

char* desired_ip = "10.0.0.10";
char* dest_ip;
char* passwd;
unsigned int pos;



// converte endereco em string para endereco em formato inteiro
unsigned int str_to_addr(char *str)
{
    unsigned int a = 0, b = 0, c = 0, d = 0, address = 0;
    sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d);
    address = (d << 24) + (c << 16) + (b << 8) + (a);
    return address;
}

// imprime payload
void print_payload( unsigned char* p, unsigned int p_len )
{
	unsigned int i = 0;
	unsigned char* aux = (unsigned char*) kmalloc(p_len+1, sizeof(unsigned char));
	for(i = 0; i < p_len; i++)
		aux[i] = p[i];
	pr_info("payload = %s", aux);
	kfree(aux);
}

// limpa variavel passwd
void clean_passwd( char* p, unsigned int p_len )
{
	unsigned int i = 0;
	for(i = 0; i < p_len; i++)
		p[i] = '\0';
	pos = 0;
}

// copia payload do pacote para uma outra variavel
void copy_payload( char* p, char* cp, unsigned int p_len )
{
	unsigned int i = 0;
	for(i = 0; i < p_len; i++)
		cp[i] = p[i];
	pos = 0;
}

// funcao hook para interceptar e modificar pacote
unsigned int intercept(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    socket_buffer = skb;												// pacote
    
    if (!socket_buffer) return NF_ACCEPT;								// pacote nulo
		
    ip_header = (struct iphdr *)skb_network_header(socket_buffer);		// ponteiro para inicio do cabecalho IP do pacote
    
    if (!ip_header) return NF_ACCEPT;									// pacote não possui cabecalho IP
		 
        
    
    if(skb_is_nonlinear(socket_buffer))									// verifica se payload estah fragmentado em mais de um buffer
		skb_linearize(socket_buffer);									// considera o payload como nao fragmentado. Pode-se dropar o pacote, se preferir 
    
    
    
	//socket_buffer->ip_summed = CHECKSUM_NONE; //stop offloading
	//socket_buffer->csum_valid = 0;
	//ip_header->check = 0;
	//ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);
	
	
	
	// verifica se o endereco destino do pacote eh o desejado 
	dest_ip = (char*) kmalloc(16, sizeof(char));
	sprintf( dest_ip, "%d.%d.%d.%d", NIPQUAD(ip_header->daddr) );
	if ( strcmp( dest_ip, desired_ip ) != 0 ) return NF_ACCEPT;
	kfree(dest_ip);

	
	// trata cada tipo de protocolo da camada de transporte
	switch(ip_header->protocol)
	{
		case IPPROTO_UDP:	// protocolo UDP
			
			pr_info("######## UDP ########\n");
			pr_info("IP origem: %d.%d.%d.%d\n", NIPQUAD(ip_header->saddr));
			pr_info("IP destino: %d.%d.%d.%d\n", NIPQUAD(ip_header->daddr));
			
			new_payload			= "very easy\r\n";														// novo payload a ser inserido no datagrama
			new_payload_len 	= (unsigned int) strlen( new_payload );									// tamanho do novo payload
			
			
			
			udp_header		= udp_hdr(socket_buffer);													// ponteiro para inicio do cabecalho UDP
			
			payload			= (unsigned char *)((unsigned char *)udp_header + sizeof(struct udphdr));	// o payload (dados ou mensagem) inicia logo apos o cabecalho UDP
			payload_len		= ntohs(udp_header->len) - sizeof(struct udphdr);							// tamanho do payload eh o tamanho total do segmento UDP menos o cabecalho UDP
			tail			= skb_tail_pointer(socket_buffer);											// ponteiro para o fim dos dados do sk_buff. Dados = ethernet + ip + udp + payload 
			
			
			pr_info("[ANTES]");
			print_payload(payload, payload_len);


			// redimensiona o espaco ocupado pelo payload no pacote/buffer. Redimensionar espaco antes de por o novo payload
			if(new_payload_len < payload_len)
			{
				// diminui o espaco se novo payload for menor que o payload atual
				skb_trim(socket_buffer, socket_buffer->data_len - payload_len + new_payload_len); // tamanho total dos dados do sk_buff menos a diferenca absoluta entre os payloads
				//pr_info("MENOR\n");
			}
			else if(new_payload_len > payload_len)
			{
				//pr_info("MAIOR\n");
				int delta = new_payload_len - payload_len;
				if (delta > skb_tailroom(socket_buffer))				// se o tamanho do novo payload ultrapassar o tailroom (for maior que o fim do pacote original) o pacote eh dropado
				{
					pr_info("[DROP]: novo payload maior que tailroom");
					return NF_DROP;
				}
				skb_put(socket_buffer,delta);							// aumenta o espaco do payload
			}

			memcpy(payload,new_payload,new_payload_len);				// copia o novo payload para o datagrama
			
			
			
			
			pr_info("[DEPOIS]");
			print_payload( payload, new_payload_len);
				
			// recalcula tamanho total do pacote IP
			ip_header->tot_len	= htons(ntohs(ip_header->tot_len) - payload_len + new_payload_len);
			
			// atualiza checksum do segmento UDP (cabecalho UDP + payload)
			udp_header			= udp_hdr(socket_buffer);
			socket_buffer->csum	= 0;
			udplen				= ntohs(udp_header->len) - payload_len + new_payload_len; //udplen = ntohs(ip_header->tot_len) - ip_header->ihl*4;
			udp_header->len		= htons(udplen);
			udp_header->check	= 0;
			udp_header->check	= udp_v4_check(udplen,ip_header->saddr, ip_header->daddr, csum_partial((char *)udp_header, udplen, 0));
			
			pr_info("###### FIM UDP ######\n");
			
		break;

		
		
		
		
		
		case IPPROTO_TCP:	// protocolo TCP
		
			pr_info("######## TCP ########\n");
			pr_info("IP origem: %d.%d.%d.%d\n", NIPQUAD(ip_header->saddr));
			pr_info("IP destino: %d.%d.%d.%d\n", NIPQUAD(ip_header->daddr));
			
			tcp_header = tcp_hdr(socket_buffer);														// ponteiro para inicio do cabecalho TCP
			
			payload			= (unsigned char *)((unsigned char *)tcp_header + (tcp_header->doff * 4));	// payload do TCP logo apos o cabecalho TCP mais o data offset (tamanho do cabecalho)
			payload_len		= ntohs(ip_header->tot_len) - ip_hdrlen(skb) - tcp_header->doff*4;			// tamanho do payload = tamanho total do pacote ip menos os cabecalhos ip e tcp;
																										// doff = data offset -> tamanho (em palavras de 32 bits) do cabecalho tcp;
																										// multiplica-se doff por 4 para transformar a informacao de palavra para bytes
			tail			= skb_tail_pointer(socket_buffer);											// ponteiro para fim dos dados do sk_buff. Dados = ethernet + ip + tcp + payload
			
			pr_info("[ANTES]");
			print_payload(payload, payload_len);
			
			
			// o correto eh checar antes se o tamanho do novo payload eh diferente
			// neste caso/exemplo nao sera necessario pois o tamanho permanece o mesmo
			copy_payload( payload, passwd, payload_len );												// copia o novo payload para o pacote
			
			
			if(strcmp(passwd, "PASS 12346\r\n") == 0) payload[9] = '5'; // demonstracao de caso. Modificacao de conteudo (senha) do payload do pacote
			clean_passwd(passwd, 100); // limpa variavel auxiliar
			
			pr_info("[DEPOIS]");
			print_payload(payload, payload_len);
			
			// atualiza checksum do segmento TCP (cabecalho TCP + payload)
			tcp_header			= tcp_hdr(socket_buffer);
			skb->csum			= 0;
			tcplen				= ntohs(ip_header->tot_len) - ip_header->ihl*4; // tot_len = tamanho total do pacote ip (em bytes); ihl = tamanho do cabecalho ip (em palavra)
			tcp_header->check	= 0;
			tcp_header->check	= tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr, csum_partial((char *)tcp_header, tcplen, 0));
			
			pr_info("###### FIM TCP ######\n");
			
		break;
	}
	
	// atualiza checksum do pacote do cabecalho IP
	ip_header->check = htons(0);
	ip_header->check = ip_fast_csum((unsigned char *) ip_header,ip_header->ihl);
	
	return NF_ACCEPT; // aceita pacote;
}

// funcao de inicializacao do modulo do kernel
static int __init init_main(void)
{
	passwd = (char*) kmalloc(100, sizeof(char));	// variavel auxiliar para demonstracao de caso
	clean_passwd(passwd, 100);						// limpando variavel auxiliar
	
	
	nfho.hook     = intercept; 						// ponteiro para funcao hook criada
	nfho.hooknum  = NF_INET_PRE_ROUTING; 			// a funcao intercept executara no pre-roteamento hook do netfilter
	nfho.pf       = PF_INET; 						// pf: protocol family. Neste caso, apenas IPv4
	nfho.priority = NF_IP_PRI_FIRST; 				// informa ao netfilter que esse hook deve ser executado "primeiro"
	nf_register_net_hook(&init_net, &nfho); 		// registrando a funcao hook criada
													// init_net (initial network namespace) eh uma instancia de um "struct net"
													// que inclui a interface de loopback e todas as interfaces fisicas
	
	
	return 0;
}

// funcao de finalizacao do modulo do kernel
static void __exit exit_main(void)
{
	nf_unregister_net_hook(&init_net, &nfho); 		// cancela registro da funcao hook
}

module_init(init_main);
module_exit(exit_main);

    
    
    
