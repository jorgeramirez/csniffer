/**
 * programa_usuario es un programa que permite al usuario 
 * establecer las reglas de filtrado a ser utilizadas por 
 * el modulo_sniffer. Dichas reglas son enviadas al 
 * modulo utilizando Generic Netlink
 * 
 * Autor: Jorge Ramirez <jorgeramirez1990@gmail.com>.
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
#include<arpa/inet.h>
#include<gtk/gtk.h>
#define VERSION_NR 1
#define LINE_SIZE 200

// atributos soportados por nuestra familia Generic Netlink
enum{
	ATTR_UNSPEC ,
	ATTR_ADDR ,
	ATTR_PORT ,
	ATTR_WAY ,
	__ATTR_MAX ,
};

#define ATTR_MAX ( __ATTR_MAX - 1)

// comandos soportados por nuestra familia Generic Netlink

enum{
	CMD_UNSPEC ,
	CMD_ADD ,
	CMD_DEL ,
	__CMD_MAX ,
};

#define CMD_MAX ( __CMD_MAX - 1)

// El socket netlink.
struct nl_handle *sock; 

// Entero que representara a la familia de generic netlink
int family;


/* funcion utilizada para convertir una cadena, que representa a una
 * direccion IP, a un entero de 32 bits sin signo.
 */
uint32_t ip_a_u32(char *d){
	uint32_t ip;
	int dir[4];
	sscanf(d, "%d.%d.%d.%d", &dir[0], &dir[1], &dir[2], &dir[3]);
	/* (primer octeto * 256³) + (segundo octeto * 256²) + 
	 * (tercer octeto * 256) + (cuarto octeto)
	*/
	ip = dir[0] * 256 * 256 * 256 + dir[1] * 256 * 256 +
			dir[2] * 256 + dir[3];
	return ip;	
}

/* funcion utilizada para construir un mensaje con el formato estandar de
 * mensaje de Generic Netlink
 */

struct nl_msg* construir_msg(int cmd_type){
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


// CallBack para la opcion Ver->Log del Sistema
void on_log_item_activate(GtkObject *object, gpointer user_data){
	char linea[LINE_SIZE];
	GtkWidget *text_view = gtk_text_view_new();
	GtkTextBuffer *text_buffer = gtk_text_view_get_buffer(text_view);
	FILE *log_file = fopen("/var/log/messages.log", "r");
	if(!log_file){
		log_file = fopen("/var/log/messages", "r");
        if(!log_file){
            return;
        }
    }
	while((fgets(linea, LINE_SIZE, log_file)) != NULL){
		gtk_text_buffer_insert_at_cursor(text_buffer, linea, -1);
	}
	fclose(log_file);
	GtkWidget *ventana_principal = (GtkWidget *)user_data;
	GtkWidget *vent_log = gtk_dialog_new_with_buttons(
						"Log del Sistema",
						ventana_principal,
						GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
						"Salir",
						GTK_RESPONSE_ACCEPT,						
						NULL);
	GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(vent_log));
	gtk_text_view_set_buffer(GTK_TEXT_VIEW(text_view), text_buffer);
	GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_add_with_viewport(sw, text_view);
	gtk_container_add(GTK_CONTAINER(content_area), sw);	
	gtk_window_resize(vent_log, 710, 400);
	gtk_widget_show_all(vent_log);
	gint res = gtk_dialog_run(GTK_DIALOG(vent_log));
	switch(res){
		case GTK_RESPONSE_ACCEPT:
				break;
	}
	gtk_widget_destroy(vent_log);
}

/* Funcion para validar los datos
 * Retorna 1 si los datos son validos, 
 * Si los datos son invalidos, muestra una ventana de error y retorna 0.
 */
int validar_datos(char *dir, char *port, char sentido, GtkWidget *ventana_principal){
	int len_dir = strlen(dir);
	GtkWidget *vent_error, *content_area;
	if(len_dir < 7 || len_dir > 15 || strcmp(port,"") == 0 || 
								(sentido != 'o' && sentido != 'd')){
		vent_error = gtk_dialog_new_with_buttons(
					"Error",
					ventana_principal,
					GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
					GTK_STOCK_OK,
					GTK_RESPONSE_ACCEPT,
					NULL);
		content_area = gtk_dialog_get_content_area(GTK_DIALOG(vent_error));
		GtkWidget *error_msg = gtk_label_new("Error: Uno o mas datos son invalidos.");
		gtk_container_add(GTK_CONTAINER(content_area), error_msg);
		gtk_widget_show_all(vent_error);
		int res = gtk_dialog_run(vent_error);
		if(res == GTK_RESPONSE_ACCEPT)
			;
		gtk_widget_destroy(vent_error);
		return 0;
	}
	return 1;
}

// CallBack para la opcion Operaciones->Agregar Regla
void on_add_regla_item_activate(GtkObject *object, gpointer user_data){
	GtkWidget *ventana_principal = (GtkWidget *)user_data;
	GtkWidget *vent_add = gtk_dialog_new_with_buttons(	
						"Nueva regla de filtrado",
						ventana_principal,
						GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
						GTK_STOCK_OK,
						GTK_RESPONSE_ACCEPT,
						GTK_STOCK_CANCEL,
						GTK_RESPONSE_CANCEL,
						NULL);
	gtk_window_set_default_size(vent_add, 300, 200);
	GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(vent_add));
	
	GtkWidget *ip_texto = gtk_entry_new();
	GtkWidget *ip_label = gtk_label_new("IP");
	GtkWidget *puerto_texto = gtk_entry_new();
	GtkWidget *puerto_label = gtk_label_new("Puerto");
	GtkWidget *sentido_texto = gtk_entry_new();	
	GtkWidget *sentido_label = gtk_label_new("Sentido");
	
	GtkWidget *hbox_ip = gtk_hbox_new(TRUE, 2);
	gtk_box_pack_start(GTK_BOX(hbox_ip), ip_label, FALSE, FALSE, 2);
	gtk_box_pack_start(GTK_BOX(hbox_ip), ip_texto, TRUE, FALSE, 2);
	gtk_container_add(GTK_CONTAINER(content_area), hbox_ip);
	
	GtkWidget *hbox_puerto = gtk_hbox_new(TRUE, 2);
	gtk_box_pack_start(GTK_BOX(hbox_puerto), puerto_label, FALSE, FALSE, 2);
	gtk_box_pack_start(GTK_BOX(hbox_puerto), puerto_texto, TRUE, FALSE, 2);
	gtk_container_add(GTK_CONTAINER(content_area), hbox_puerto);
	
	GtkWidget *hbox_sentido = gtk_hbox_new(TRUE, 2);
	gtk_box_pack_start(GTK_BOX(hbox_sentido), sentido_label, FALSE, FALSE, 2);
	gtk_box_pack_start(GTK_BOX(hbox_sentido), sentido_texto, TRUE, FALSE, 2);
	gtk_container_add(GTK_CONTAINER(content_area), hbox_sentido);
	
	gtk_widget_show_all(vent_add);
	
	gint res = gtk_dialog_run(GTK_DIALOG(vent_add));
	
	struct nl_msg *msg;
	char *dir;
	uint32_t ip;
	char *port;
	unsigned short puerto;
	unsigned char sentido;
	int valido;
	switch(res){
		case GTK_RESPONSE_ACCEPT:
			// enviar mensaje al modulo del kernel.
			dir = gtk_entry_get_text(GTK_ENTRY(ip_texto));
			ip = ip_a_u32(dir);
			port = gtk_entry_get_text(GTK_ENTRY(puerto_texto));
			puerto = atoi(port);
			sentido = gtk_entry_get_text(GTK_ENTRY(sentido_texto))[0];
			valido = validar_datos(dir, port, sentido, ventana_principal);
			if(!valido)
				break;
			msg = construir_msg(CMD_ADD);
			nla_put_u32(msg, ATTR_ADDR, ip);
			nla_put_u16(msg, ATTR_PORT, puerto) ;
			nla_put_u8(msg, ATTR_WAY, sentido);
			// Paso 7: Enviar el mensaje por el socket netlink.
			nl_send_auto_complete(sock, msg) ;
			
			//Liberamos la memoria ocupada por el mensaje
			nlmsg_free(msg);
			break;
		case GTK_RESPONSE_CANCEL:
			break;
	}
	gtk_widget_destroy(vent_add);
}


// CallBack para la opcion Operaciones->Eliminar Regla
void on_rmv_regla_item_activate(GtkObject *object, gpointer user_data){
	GtkWidget *ventana_principal = (GtkWidget *)user_data;
	GtkWidget *vent_rmv = gtk_dialog_new_with_buttons(	
						"Eliminar regla de filtrado",
						ventana_principal,
						GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
						GTK_STOCK_OK,
						GTK_RESPONSE_ACCEPT,
						GTK_STOCK_CANCEL,
						GTK_RESPONSE_CANCEL,
						NULL);
	gtk_window_set_default_size(vent_rmv, 300, 200);
	GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(vent_rmv));
	
	GtkWidget *ip_texto = gtk_entry_new();
	GtkWidget *ip_label = gtk_label_new("IP");
	GtkWidget *puerto_texto = gtk_entry_new();
	GtkWidget *puerto_label = gtk_label_new("Puerto");
	GtkWidget *sentido_texto = gtk_entry_new();	
	GtkWidget *sentido_label = gtk_label_new("Sentido");
	
	GtkWidget *hbox_ip = gtk_hbox_new(TRUE, 2);
	gtk_box_pack_start(GTK_BOX(hbox_ip), ip_label, FALSE, FALSE, 2);
	gtk_box_pack_start(GTK_BOX(hbox_ip), ip_texto, TRUE, FALSE, 2);
	gtk_container_add(GTK_CONTAINER(content_area), hbox_ip);
	
	GtkWidget *hbox_puerto = gtk_hbox_new(TRUE, 2);
	gtk_box_pack_start(GTK_BOX(hbox_puerto), puerto_label, FALSE, FALSE, 2);
	gtk_box_pack_start(GTK_BOX(hbox_puerto), puerto_texto, TRUE, FALSE, 2);
	gtk_container_add(GTK_CONTAINER(content_area), hbox_puerto);
	
	GtkWidget *hbox_sentido = gtk_hbox_new(TRUE, 2);
	gtk_box_pack_start(GTK_BOX(hbox_sentido), sentido_label, FALSE, FALSE, 2);
	gtk_box_pack_start(GTK_BOX(hbox_sentido), sentido_texto, TRUE, FALSE, 2);
	gtk_container_add(GTK_CONTAINER(content_area), hbox_sentido);
	
	gtk_widget_show_all(vent_rmv);
	
	gint res = gtk_dialog_run(GTK_DIALOG(vent_rmv));
	
	struct nl_msg *msg;
	char *dir;
	uint32_t ip;
	char *port;
	unsigned short puerto;
	unsigned char sentido;
	int valido;
	switch(res){
		case GTK_RESPONSE_ACCEPT:
			// enviar mensaje al modulo del kernel.
			dir = gtk_entry_get_text(GTK_ENTRY(ip_texto));
			ip = ip_a_u32(dir);
			port = gtk_entry_get_text(GTK_ENTRY(puerto_texto));
			puerto = atoi(port);
			sentido = gtk_entry_get_text(GTK_ENTRY(sentido_texto))[0];
			valido = validar_datos(dir, port, sentido, ventana_principal);
			if(!valido)
				break;			
			msg = construir_msg(CMD_DEL);
			nla_put_u32(msg, ATTR_ADDR, ip);
			nla_put_u16(msg, ATTR_PORT, puerto) ;
			nla_put_u8(msg, ATTR_WAY, sentido);
			// Paso 7: Enviar el mensaje por el socket netlink.
			nl_send_auto_complete(sock, msg) ;
			
			//Liberamos la memoria ocupada por el mensaje
			nlmsg_free(msg);
			break;
		case GTK_RESPONSE_CANCEL:
			break;
	}
	gtk_widget_destroy(vent_rmv);
}


// Procedimiento que crear la barra de menu de la aplicacion.
void crear_menu_bar(GtkWidget *ventana_principal, GtkWidget *vbox){
	//barra de menus
	GtkWidget *menu_bar = gtk_menu_bar_new();
	gtk_box_pack_start(GTK_BOX(vbox), menu_bar, FALSE, FALSE, 2);
	
	//Elementos de la barra de menus.
	GtkWidget *arch_item = gtk_menu_item_new_with_label("Archivo");
	GtkWidget *ver_item = gtk_menu_item_new_with_label("Ver");
	GtkWidget *op_item = gtk_menu_item_new_with_label("Operaciones");
	
	// Menu Archivo
	GtkWidget *arch_menu, *salir_item;
	arch_menu = gtk_menu_new();
	salir_item = gtk_menu_item_new_with_label("Salir");
	gtk_menu_shell_append(GTK_MENU(arch_menu), salir_item);
	g_signal_connect(G_OBJECT(salir_item), 
					 "activate", 
					 G_CALLBACK(gtk_main_quit), 
					 NULL);
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(arch_item), arch_menu);
	gtk_menu_shell_append(GTK_MENU_BAR(menu_bar), arch_item);
	
	//Menu operaciones.
	GtkWidget *op_menu, *add_regla_item, *rmv_regla_item, *listar_item;
	op_menu = gtk_menu_new();
	add_regla_item = gtk_menu_item_new_with_label("Agregar regla");
	rmv_regla_item = gtk_menu_item_new_with_label("Remover regla");
	gtk_menu_shell_append(GTK_MENU(op_menu), add_regla_item);
	gtk_menu_shell_append(GTK_MENU(op_menu), rmv_regla_item);
	g_signal_connect(G_OBJECT(add_regla_item),
					 "activate",
					 G_CALLBACK(on_add_regla_item_activate), 
					 ventana_principal);
	g_signal_connect(G_OBJECT(rmv_regla_item),
					 "activate",
					 G_CALLBACK(on_rmv_regla_item_activate), 
					 ventana_principal);
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(op_item), op_menu);
	gtk_menu_shell_append(GTK_MENU_BAR(menu_bar), op_item);		
	
	// Menu Ver
	GtkWidget *ver_menu, *log_item;
	ver_menu = gtk_menu_new();
	log_item = gtk_menu_item_new_with_label("Log del Sistema");
	gtk_menu_shell_append(GTK_MENU(ver_menu), log_item);
	g_signal_connect(G_OBJECT(log_item),
					 "activate",
					 G_CALLBACK(on_log_item_activate), 
					 ventana_principal);
	gtk_menu_item_set_submenu(GTK_MENU_ITEM(ver_item), ver_menu);
	gtk_menu_shell_append(GTK_MENU_BAR(menu_bar), ver_item);
	
	//Para que nuestro barra de menu no ocupe toda la ventana.
	GtkWidget *hbox_aux = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_end(GTK_BOX(vbox), hbox_aux, TRUE, TRUE, 2);
}


int main(int argc, char *argv[]){
	// Paso 1: Crear un manejador de socket netlink
	sock = nl_handle_alloc();
	
	// Paso 2: Conectar al socket netlink generico
	genl_connect(sock);

	/* Paso 3: Preguntar al kernel para que resuelva el nombre de la 
	  familia y nos devuelva el id.*/
	family = genl_ctrl_resolve(sock, "SNF_GENL");
	gtk_init(&argc, &argv);
	GtkWidget *ventana_principal = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	GtkWidget *vbox = gtk_vbox_new(FALSE, 0);	
	gtk_window_set_title(ventana_principal, "SNIFFER 1.0");
	gtk_window_set_default_size(ventana_principal, 500, 400);
	gtk_window_set_deletable(ventana_principal, TRUE);	
	gtk_container_add(GTK_CONTAINER(ventana_principal), vbox);
	crear_menu_bar(ventana_principal, vbox);

	g_signal_connect(G_OBJECT(ventana_principal), 
					 "destroy",
					 G_CALLBACK(gtk_main_quit),
					 NULL);
	gtk_widget_show_all(ventana_principal);
	gtk_main();
	return 0;
}
