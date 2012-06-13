/**
 * modulo_sniffer es un modulo del kernel que registra un handler
 * para paquetes del tipo ETH_P_IP, con el fin de analizar los
 * paquetes que cumplen con ciertos requisitos impuestos por el 
 * proceso de espacio de usuario llamado programa_usuario.
 * 
 * Autor: Jorge Ramirez <jorgeramirez1990@gmail.com>.
 * Carrera: Ingenieria Informatica FP-UNAirez.
 * 
 * Changes:
 *     11/05/2011 remover NIPQUAD debido ya no se usa, utilizar el formato %pI4 
 *                para printk() el mismo recibe un u32	dst_ip[4]
 **/

#include<linux/module.h> // para todos los modulos
#include<linux/init.h>	// para las macros entry/exit
#include<linux/kernel.h> // para usar las macros printk, NIPQUAD
#include<linux/list.h>	// para utilizar struct list_head
#include<linux/slab.h> // para utilizar kmalloc() y kfree()
#include<net/genetlink.h> //Generic Netlink.
#include<linux/tcp.h> // define la estructura struct tcphdr
#include<linux/udp.h> // define la estructura struct udphdr
#include<linux/ip.h> // define la estructura struct iphdr
#include<linux/in.h> //define los posibles protocolos de capa de transporte 


//definimos los atributos que seran pasados utilizando Generic Netlink.
enum {
	ATTR_UNSPEC ,
    ATTR_ADDR ,
    ATTR_PORT ,
    ATTR_WAY ,
    __ATTR_MAX ,
};
#define ATTR_MAX (__ATTR_MAX - 1)

//definimos los comandos que seran pasados utilizando Generic Netlink.
enum {
	CMD_UNSPEC ,
    CMD_ADD ,
    CMD_DEL ,
    __CMD_MAX ,
};
#define CMD_MAX (__CMD_MAX - 1)

/* Definimos las politicas. Estas polıticas determinan entre otras cosas
 * el tipo de dato de nuestros atributos. Asi si un cliente nos envia 
 * informacion con otro tipo de dato, la informacion va a ser filtrada 
 * por Generic Netlink y no nos va a llegar.
 */
static struct nla_policy snf_genl_policy[ATTR_MAX + 1] = {
	 [ATTR_ADDR] = {.type = NLA_U32},
     [ATTR_PORT] = {.type = NLA_U16},
     [ATTR_WAY] = {.type = NLA_U8},
};

/* Definimos nuestra estructura struct regla que utilizaremos
 * para filtrar los paquetes que seran analizados.
 */
struct regla{
	struct list_head lista;
	uint32_t ip; //los bits deben estar en el orden htonl
	unsigned short puerto; // htons
	unsigned char sentido;
};

/*Creamos una familia Generic Netlink que es la que maneja nuestro
 * protocolo netlink.
 */
#define VERSION_NR 1
static struct genl_family snf_genl_family = {
	.id = GENL_ID_GENERATE,      //genetlink tiene que generar el id
    .hdrsize = 0,
    .name = "SNF_GENL",        //nombre de la familia
    .version = VERSION_NR,       //numero de version
    .maxattr = ATTR_MAX,         // Cantidad maxima de atributos
};

//El handler que vamos a registrar.
struct packet_type ip_handler; 

//lista que contiene las reglas de filtrado.
struct regla *cabecera = NULL;

 
struct regla * crear_regla(uint32_t direccion, unsigned short puerto, 
							unsigned char sentido){
	struct regla *tmp = (struct regla *)kmalloc(sizeof(struct regla), 
												GFP_KERNEL);
	tmp->ip = direccion;
	tmp->puerto = puerto;
	tmp->sentido = sentido;
	return tmp;
}


/*Definimos la funcion cmd_add_handler, que agregara una nueva regla
 * a nuestra lista de reglas que utilizamos para filtrar datos.
 */
int cmd_add_handler(struct sk_buff *skb, struct genl_info *info){
	struct nlattr *na;
    uint32_t addr = 0;
    unsigned short port = 0;
    unsigned char way = ' ';
    printk(KERN_INFO "\nAgregando regla...");
    // Obtenemos el atributo de direccion 
    na = info->attrs[ATTR_ADDR];
    if(na){
		// Obtenemos la direccion
        addr = nla_get_u32(na) ;
        // htonl(addr); //cambia el orden de los bits.
        uint32_t aux = htonl(addr);
        printk(KERN_INFO "\n\nAddress : %pI4\n", &aux);
    }else
        printk(KERN_INFO "\nNo info->attrs %i \n", ATTR_ADDR);

    // Obtenemos el atributo de puerto
    na = info->attrs[ATTR_PORT];
    if(na){
		// Obtenemos el puerto
        port = nla_get_u16(na);
        printk(KERN_INFO "Port : %d \n", port);
    }else
        printk(KERN_INFO"No info->attrs %i \n", ATTR_PORT);
    // Obtenemos el atributo de direccion.
    na = info->attrs[ATTR_WAY];
    if(na){
		way = nla_get_u8(na);
		printk(KERN_INFO "Way: %c \n", way);
	}else
		printk(KERN_INFO "No info->attrs %i \n", ATTR_WAY);
		
    /* Creamos una nueva regla con los atributos obtenidos, y la añadimos
     * a nuestra lista de reglas utilizando el "nodo regla" cabecera de la
     * lista.
     * Hay que tener en cuenta el endiannes del u16 que representa el
     * puerto. Desde espacio de usuario se le envía en el endiann de 
     * x86 pero al comparar con el campo de struct iphdr, el endiannes 
     * es distinto, por eso utilizamos la macro htons() para el puerto.
     */
    struct regla *nueva_regla;
    nueva_regla = crear_regla(htonl(addr), htons(port), way);
	
	list_add(&nueva_regla->lista, &cabecera->lista);
	uint32_t aux = htonl(addr);
    printk(KERN_INFO "\nRegla agregada [ IP: %pI4, Puerto: %hu, Sentido: \"%c\" ]", 
				&aux, port, way);
    return 0;
}

/*Definimos la funcion cmd_del_handler, que eliminara una regla
 * de nuestra lista de reglas que hemos definido.
 */
int cmd_del_handler(struct sk_buff *skb, struct genl_info *info){
	struct nlattr *na;
    uint32_t addr = 0;
    unsigned short port = 0;
    unsigned char way = ' ';
    
	if(list_empty(&cabecera->lista) != 0)
		return 1;
    
    printk(KERN_INFO "\nEliminando regla...");
    // Obtenemos el atributo de direccion 
    na = info->attrs[ATTR_ADDR];
    if(na){
		// Obtenemos la direccion
        addr = nla_get_u32(na) ;
        uint32_t aux = htonl(addr);
        printk(KERN_INFO "\n\nAddress : %pI4 \n", &aux);
    }else
        printk(KERN_INFO "\nNo info->attrs %i \n", ATTR_ADDR);

    // Obtenemos el atributo de puerto
    na = info->attrs[ATTR_PORT];
    if(na){
		// Obtenemos el puerto
        port = nla_get_u16(na);
        printk(KERN_INFO "Port : %d \n", port);
    }else
        printk(KERN_INFO "No info->attrs %i \n", ATTR_PORT);
    // Obtenemos el atributo de direccion.
    na = info->attrs[ATTR_WAY];
    if(na){
		way = nla_get_u8(na);
		printk(KERN_INFO "Way: %c \n", way);
	}else
		printk(KERN_INFO "No info->attrs %i \n", ATTR_WAY);
		
    /* Eliminamos la regla de la lista de reglas que cumpla con los 
     * atributos que hemos obtenido.
     */
    struct regla *r;
    
    /* Para iterar la lista de reglas utilizamos la macro.
     * list_for_each_entry : iterate over a list of given type
     * 
     * #define list_for_each_entry(pos, head, member)
     * @pos:        the type * to use as a loop cursor.
     * @head:       the head for your list.
     * @member:     the name of the list_struct within the struct.
     */
	uint32_t aux = htonl(addr);
	list_for_each_entry(r, &cabecera->lista, lista){
		if(r->ip == aux && r->puerto == htons(port) && r->sentido == way){
			//eliminamos la regla.
			list_del(&r->lista);
			printk(KERN_INFO "\nRegla eliminada [ IP: %pI4, Puerto: %hu, Sentido: \"%c\" ]", 
							&aux, port, way);
			//liberamos la memoria que ocupa el elemento de la lista.
			kfree(r); 
			return 0;
		}
	}
	printk(KERN_INFO "\nRegla [ IP: %pI4, Puerto: %hu, Sentido: \"%c\" ] no encontrada", 
				&aux, port, way);			
    return 0;
}

/* Creamos un vector de estructuras struct genl_ops. Estas 
 * estructuras son las que definen las operaciones netlink. Estas 
 * operaciones asocian un comando a una funcion handler. Por lo que 
 * cada vez que se envie desde un proceso un mensaje con un comando, 
 * automaticamente se invoca a la funcion handler para ese comando. 
 * Tambien se especifica la politica, por lo que solamente se invoca
 * a la funcion si los atributos cumplen con los requerimientos.
 */
struct genl_ops snf_genl_ops[] = {
	{
		.cmd = CMD_ADD ,
        .flags = 0 ,
        .policy = snf_genl_policy ,
        .doit = cmd_add_handler ,
        .dumpit = NULL ,
    },
    {
        .cmd = CMD_DEL ,
        .flags = 0 ,
        .policy = snf_genl_policy ,
        .doit = cmd_del_handler ,
        .dumpit = NULL ,
    },
};


void __imprimir_puerto(struct sk_buff *skb, struct iphdr *ip_hdr, struct regla *r, char way){
	struct tcphdr *tcp_hdr;
	struct udphdr *udp_hdr;
	switch(ip_hdr->protocol){
		case IPPROTO_TCP:
			tcp_hdr = (struct tcphdr *)(skb->data + ip_hdr->ihl * 4);
			if(tcp_hdr->source == r->puerto && way == 'o'){
				printk(KERN_INFO "\nInformacion de Capa de Red");
				printk(KERN_INFO "\t|__IP origen: %pI4", &ip_hdr->saddr);
				printk(KERN_INFO "Informacion de Capa de Transporte");
				printk(KERN_INFO "\t|__Protocolo: TCP");				
				printk(KERN_INFO "\t|__Puerto origen: %hu", ntohs(tcp_hdr->source));
				printk(KERN_INFO "\t|__Numero de secuencia: %u", ntohl(tcp_hdr->seq));
				printk(KERN_INFO "\t|__ACK: %u", ntohl(tcp_hdr->ack_seq));
			}else if(tcp_hdr->dest == r->puerto && way == 'd'){
				printk(KERN_INFO "\nInformacion de Capa de Red");
				printk(KERN_INFO "\t|__IP destino: %pI4", &ip_hdr->daddr);
				printk(KERN_INFO "Informacion de Capa de Transporte");
				printk(KERN_INFO "\t|__Protocolo: TCP");									
				printk(KERN_INFO "\t|__Puerto destino: %hu", ntohs(tcp_hdr->dest));
				printk(KERN_INFO "\t|__Numero de secuencia: %u", ntohl(tcp_hdr->seq));
				printk(KERN_INFO "\t|__ACK: %u", ntohl(tcp_hdr->ack_seq));	
			}
			break;
		case IPPROTO_UDP:
			udp_hdr = (struct udphdr *)(skb->data + ip_hdr->ihl * 4);
			if(udp_hdr->source == r->puerto && way == 'o'){
				printk(KERN_INFO "\nInformacion de Capa de Red");
				printk(KERN_INFO "\t|__IP origen: %pI4", &ip_hdr->saddr);
				printk(KERN_INFO "Informacion de Capa de Transporte");
				printk(KERN_INFO "\t|__Protocolo: UDP");				
				printk(KERN_INFO "\t|__Puerto origen: %hu", ntohs(udp_hdr->source));
				printk(KERN_INFO "\t|__Longitud: %hu", ntohs(udp_hdr->len));
				printk(KERN_INFO "\t|__Check Sum: %hu", ntohs(udp_hdr->check));
			}else if(udp_hdr->dest == r->puerto && way == 'd'){
				printk(KERN_INFO "\nInformacion de Capa de Red");
				printk(KERN_INFO "\t|__IP destino: %pI4", &ip_hdr->daddr);
				printk(KERN_INFO "Informacion de Capa de Transporte");
				printk(KERN_INFO "\t|__Protocolo: UDP");									
				printk(KERN_INFO "\t|__Puerto destino: %hu", ntohs(udp_hdr->dest));	
				printk(KERN_INFO "\t|__Longitud: %hu", ntohs(udp_hdr->len));
				printk(KERN_INFO "\t|__Check Sum: %hu", ntohs(udp_hdr->check));
			}			
			break;
		default:
			break;
	}
	
}

void controlar_imprimir_reglas(struct sk_buff *skb, struct iphdr *ip_hdr){
	struct regla *r;
	struct tcphdr *tcp_hdr;
	struct udphdr *udp_hdr;
	if(list_empty(&cabecera->lista) != 0){	
		//no existen reglas de filtrado.
		switch(ip_hdr->protocol){
			case IPPROTO_TCP:
				printk(KERN_INFO "\nInformacion de Capa de Red");
				printk(KERN_INFO "\t|__IP origen: %pI4", &ip_hdr->saddr);
				printk(KERN_INFO "\t|__IP destino: %pI4", &ip_hdr->daddr);
				printk(KERN_INFO "Informacion de Capa de Transporte");
				tcp_hdr = (struct tcphdr *)(skb->data + ip_hdr->ihl * 4);
				printk(KERN_INFO "\t|__Protocolo: TCP");
				printk(KERN_INFO "\t|__Puerto origen: %hu", ntohs(tcp_hdr->source));
				printk(KERN_INFO "\t|__Puerto destino: %hu", ntohs(tcp_hdr->dest));
				printk(KERN_INFO "\t|__Numero de secuencia: %u", ntohl(tcp_hdr->seq));
				printk(KERN_INFO "\t|__ACK: %u", ntohl(tcp_hdr->ack_seq));
				break;
			case IPPROTO_UDP:
				printk(KERN_INFO "\nInformacion de Capa de Red");
				printk(KERN_INFO "\t|__IP origen: %pI4", &ip_hdr->saddr);
				printk(KERN_INFO "\t|__IP destino: %pI4", &ip_hdr->daddr);
				printk(KERN_INFO "Informacion de Capa de Transporte");
				udp_hdr = (struct udphdr *)(skb->data + ip_hdr->ihl * 4);
				printk(KERN_INFO "\t|__Protocolo: UDP");
				printk(KERN_INFO "\t|__Puerto origen: %hu", ntohs(udp_hdr->source));
				printk(KERN_INFO "\t|__Puerto destino: %hu", ntohs(udp_hdr->dest));
				printk(KERN_INFO "\t|__Longitud: %hu", ntohs(udp_hdr->len));
				printk(KERN_INFO "\t|__Check Sum: %hu", ntohs(udp_hdr->check));
				break;
			default:
				break;
		}
	}else{
		list_for_each_entry(r, &cabecera->lista, lista){	
			if(r->sentido == 'o' && ip_hdr->saddr == r->ip){
				__imprimir_puerto(skb, ip_hdr, r,'o');
			}else if(r->sentido == 'd' && ip_hdr->daddr == r->ip){
				__imprimir_puerto(skb, ip_hdr, r,'d');
			}	
		}
		
	}
}

/* packet_rcv es la funcion llamada justo cuando llega un paquete a un
 * dispositivo.
 * Parametros:
 * @skb: es un puntero al buffer del paquete, 
 * @dev: es un puntero al dispositivo que obtuvo el paquete,
 * @pt: es un puntero a la estructura packet type utilizada para 
 * registrar el handler.
 */
int packet_rcv (struct sk_buff *skb , struct net_device *src , struct
    packet_type *pt , struct net_device *dst ){

	//Obtenemos la cabecera IP
	struct iphdr *ip_hdr = (struct iphdr *)skb_network_header(skb);
	
	/* Obtenemos la cabecera de capa de transporte
	 * La definicion de los posibles protocolos de capa de transporte 
	 * esta especificado en include/linux/in.h 
	 */

	/* Standard well-defined IP protocols.  */ 
	// enum { 
	//  IPPROTO_IP = 0,               /* Dummy protocol for TCP               */ 
	//  IPPROTO_ICMP = 1,             /* Internet Control Message Protocol    */ 
	//  IPPROTO_IGMP = 2,             /* Internet Group Management Protocol   */ 
	//  IPPROTO_IPIP = 4,             /* IPIP tunnels (older KA9Q tunnels use 94) */ 
	//  IPPROTO_TCP = 6,              /* Transmission Control Protocol        */ 
	//  IPPROTO_EGP = 8,              /* Exterior Gateway Protocol            */ 
	//  IPPROTO_PUP = 12,             /* PUP protocol                         */ 
	//  IPPROTO_UDP = 17,             /* User Datagram Protocol               */ 
	//  IPPROTO_IDP = 22,             /* XNS IDP protocol                     */ 
	//  IPPROTO_DCCP = 33,            /* Datagram Congestion Control Protocol */ 
	//  IPPROTO_RSVP = 46,            /* RSVP protocol                        */ 
	//  IPPROTO_GRE = 47,             /* Cisco GRE tunnels (rfc 1701,1702)    */ 
	//  IPPROTO_IPV6   = 41,          /* IPv6-in-IPv4 tunnelling              */ 
	//  IPPROTO_ESP = 50,            /* Encapsulation Security Payload protocol */ 
	//  IPPROTO_AH = 51,             /* Authentication Header protocol       */ 
	//  IPPROTO_BEETPH = 94,         /* IP option pseudo header for BEET */ 
	//  IPPROTO_PIM    = 103,         /* Protocol Independent Multicast       */ 
	//  IPPROTO_COMP   = 108,                /* Compression Header protocol */ 
	//  IPPROTO_SCTP   = 132,         /* Stream Control Transport Protocol    */ 
	//  IPPROTO_UDPLITE = 136,        /* UDP-Lite (RFC 3828)                  */ 
	//  IPPROTO_RAW    = 255,         /* Raw IP packets                       */ 
	//  IPPROTO_MAX 
	//};
	

	/*Controlamos si las cabeceras cumplen con alguna de las reglas 
	 * establecidas en conjunto_reglas, es decir, las reglas 
	 * que el usuario establecio, luego imprimimos.
	 */
	
	controlar_imprimir_reglas(skb, ip_hdr);
    return 0;
}

static int __init iniciar_modulo(void){
	printk(KERN_INFO "\nInicializando el modulo_sniffer...");
	 
	/* Inicializamos nuestra "cabecera" de la lista, es del tipo regla
	 * y es utilizada como nodo inicial, es decir, apartir de ella
	 * se genera la lista de reglas.
	 */
	cabecera = crear_regla(0, 0,'a');
	INIT_LIST_HEAD(&cabecera->lista);
	 
	//creamos y registramos el handler.
	ip_handler.type = htons(ETH_P_IP);
	ip_handler.func = packet_rcv;
	ip_handler.dev = NULL; //todos los dispositivos.
	dev_add_pack(&ip_handler); 
	 
    /* Registramos nuestra familia Generic Netlink y las operaciones, 
     * 
     * Obs: La funcion genl_register_family_with_ops no esta definida 
     * en versiones anteriores del kernel. Por eso se utiliza la forma
     * mas comun por motivos de compatibilidad.
     */
    int rc;
    char *error = "Error al registrar estructuras Generic Netlink";
    rc = genl_register_family(&snf_genl_family);
    if(rc != 0){
		printk(KERN_INFO "\n %s", error);
		return -1;
	}

	int i, band = 0;
	int n = sizeof(snf_genl_ops) / sizeof(struct genl_ops);
	for(i = 0; i < n && !band; i++){
		rc = genl_register_ops(&snf_genl_family, &snf_genl_ops[i]);
		if(rc != 0){
			printk(KERN_INFO "\n %s", error);
			genl_unregister_family(&snf_genl_family);
			band = 1;
		}
	}
}  


static void __exit finalizar_modulo(void){
	printk(KERN_INFO "\nFinalizando el modulo_sniffer...");
	
	//removemos nuestro handler.
	dev_remove_pack(&ip_handler);
	
	/*removemos nuestra familia Generic Netlink con sus operaciones.
	 * Al utilizar la funcion genl_unregister_family, ya conseguimos
	 * tambien remover las operaciones pertenecientes a dicha familia.
	 */
	genl_unregister_family(&snf_genl_family);
}  

module_init(iniciar_modulo);
module_exit(finalizar_modulo);

MODULE_AUTHOR("Jorge Ramirez"); 
MODULE_LICENSE("Dual BSD/GPL"); 
MODULE_DESCRIPTION("Sniffer, permite analizar el trafico \
entrante/saliente de una computadora.");
