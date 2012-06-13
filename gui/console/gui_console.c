/**
 * sniffer_userspace es un programa que permite al usuario 
 * establecer las reglas de filtrado a ser utilizadas por 
 * el modulo_sniffer. Dichas reglas son enviadas al 
 * modulo_sniffer utilizando Generic Netlink
 * 
 * Autor: Jorge Ramirez.
 * Carrera: Ingenieria Informatica FP-UNA
 **/

#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<unistd.h>
#include<poll.h>
#include<string.h>
#include<fcntl.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<signal.h>
#include<linux/genetlink.h> //Generic Netlink.
#include<netlink/genl/genl.h>
#include<netlink/genl/ctrl.h>
#define VERSION_NR 1

// atributos
enum{
	ATTR_UNSPEC ,
    ATTR_ADDR ,
	ATTR_PORT ,
    ATTR_WAY ,
    __ATTR_MAX ,
};

#define ATTR_MAX ( __ATTR_MAX - 1)

// comandos

enum{
	CMD_UNSPEC ,
	CMD_ADD ,
	CMD_DEL ,
	__CMD_MAX ,
};

#define CMD_MAX ( __CMD_MAX - 1)

uint32_t ip_a_u32(int dir[]){
	uint32_t ip;
	/* (primer octeto * 256³) + (segundo octeto * 256²) + 
	 * (tercer octeto * 256) + (cuarto octeto)
	*/
	ip = dir[0] * 256 * 256 * 256 + dir[1] * 256 * 256 +
			dir[2] * 256 + dir[3];
	return ip;	
}

struct nl_msg * construir_msg(int cmd_type, int family){
	struct nl_msg *msg;
	//Paso 4: construir mensaje.
	msg = nlmsg_alloc();
	//Paso 5: Llenar la cabecera con el comando y la version de la familia.
	if(cmd_type == CMD_ADD)
		genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 
					NLM_F_ECHO ,CMD_ADD ,VERSION_NR);
	else
		genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, 
					NLM_F_ECHO, CMD_DEL, VERSION_NR);
	return msg;		
}

void info_programa(){
	printf("\nSniffer version 1.0 \nAutor: Jorge Ramirez \n");	
	printf("El programa utiliza reglas de filtrado, dichas reglas \n");
	printf("se componen de una direccion IP, un Puerto y un \n");
	printf("sentido (origen \"o\" destino \"d\") \n\n");
}

void print_opciones(){
	printf("\nOpciones.");
	printf("\n1- Agregar nueva regla.");
	printf("\n2- Eliminar regla.");
	printf("\n3- Salir del programa.");
	printf("\n\nIngrese opcion: ");
}

int main(int argc, char **argv) {
	struct nl_handle *sock;
	struct nl_msg *msg;
	int family;
	unsigned short puerto;
	uint32_t direccion;
	unsigned char sentido;
	char cad[16]; // xxx.xxx.xxx.xxx
	int dir[4]; // [xxx, xxx, xxx, xxx] 	
	// Paso 1: Crear un manejador de socket netlink
	sock = nl_handle_alloc();

	// Paso 2: Conectar al socket netlink generico
	genl_connect(sock);

	/* Paso 3: Preguntar al kernel para que resuelva el nombre de la 
	  familia y nos devuelva el id.*/
	family = genl_ctrl_resolve(sock, "SNF_GENL");

	 //el primer mensaje es siempre para agregar una regla.	
	msg = construir_msg(CMD_ADD, family);
	
	// Paso 6: Llenar el cuerpo con atributos y sus valores
	
	info_programa(); //imprimimos informacion del programa.
	
	printf("\nIngrese las reglas que se utilizaran como filtros, para \
				realizar el analisis \n");
	int salir_programa = 0;
	while(1){
		printf("IP: ");
		scanf("%s", cad); getchar();
		
		//copiamos cada octeto en el array dir[]
		sscanf(cad, "%d.%d.%d.%d", &dir[0], &dir[1], &dir[2], &dir[3]);

		
		printf("\nPuerto: ");
		// %hu para unsigned short int
		scanf("%hu", &puerto); getchar();
		while(1){
			printf("\nSentido, \"o\" para puerto origen, \"d\" para destino: ")	;
			scanf("%c", &sentido);getchar();
			if(sentido == 'o' || sentido == 'd')
				break;
			else
				printf("\nOpcion invalida!!");
		}	
		//convertimos nuestra direccion ip a un numero entero de 32 bits.
		direccion = ip_a_u32(dir);
		
		nla_put_u32(msg, ATTR_ADDR, direccion);
		nla_put_u16(msg, ATTR_PORT, puerto) ;
		nla_put_u8(msg, ATTR_WAY, sentido);

		// Paso 7: Enviar el mensaje por el socket netlink.
		nl_send_auto_complete(sock, msg) ;
		
		//Liberamos la memoria ocupada por el mensaje
		nlmsg_free(msg);
		
		int opcion, salir_opciones = 0;
		print_opciones();
		while(1){
			scanf("%d", &opcion);
			switch(opcion){
				case 1:
					msg = construir_msg(CMD_ADD, family);
					salir_opciones = 1;
					break;
				case 2:
					msg = construir_msg(CMD_DEL, family);
					salir_opciones = 1;
					break;
				case 3:
					salir_programa = 1;
					salir_opciones = 1;
					break;
				default:
					printf("\nOpcion invalida!!! \n");
					break;
			}
			if(salir_opciones)
				break;
			else
				printf("\nIngrese opcion: ");
		}
		if(salir_programa)
			break;
	}
    return 0;
}
