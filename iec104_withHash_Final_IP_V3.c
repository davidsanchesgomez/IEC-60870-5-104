/***************************************************************************
 iec104_withHash.c
 Toma como codigo de partida la practica de redes de comunicaciones de la UAM EPS,
 cuyos autores son Jose Luis Garcia Dorado, Jorge E. Lopez de Vergara Mendez, Rafael Leira, Javier Ramos
 2018 EPS-UAM
 Compila: gcc -Wall -o iec104 iec104_withHash.c -lpcap
 Autor: David Sanches Gómez
 2018 EPS-UAM
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>

#include <math.h>
#include <stdbool.h>

//hash
#include <stdbool.h>
#define SIZE 10000 

/*Definicion de constantes ******************************************************************************************/
#define ETH_ALEN      6      						 /* Tamanio de la direccion ethernet          				    */
#define ETH_HLEN      14    						 /* Tamanio de la cabecera ethernet          			        */
#define ETH_TLEN      2      						 /* Tamanio del campo tipo ethernet            				    */
#define ETH_FRAME_MAX 1514   						 /* Tamanio maximo la trama ethernet (sin CRC) 				    */
#define ETH_FRAME_MIN 60   						     /* Tamanio minimo la trama ethernet (sin CRC) 				    */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) 	 /* Tamano maximo y minimo de los datos de una trama ethernet   */
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4									 /* Tamanio de la direccion IP								    */
#define OK 0
#define ERROR 1
#define PACK_READ 1
#define PACK_ERR -1
#define TRACE_END -2
#define NO_FILTER 0

/*ASDU types (TypeId) ***********************************************************************************************/
#define M_SP_NA_1  1      /* single-point information 																*/
#define M_DP_NA_1  3      /* double-point information 																*/
#define M_ST_NA_1  5      /* step position information 																*/
#define M_BO_NA_1  7      /* bitstring of 32 bits 																	*/
#define M_ME_NA_1  9      /* measured value, normalized value 														*/
#define M_ME_NB_1  11     /* measured value, scaled value 															*/
#define M_ME_NC_1  13     /* measured value, short floating point number 											*/
#define M_IT_NA_1  15     /* integrated totals 																		*/
#define M_PS_NA_1  20     /* packed single-point information with status change detection 							*/
#define M_ME_ND_1  21     /* measured value, normalized value without quality descriptor 							*/
#define M_SP_TB_1  30     /* single-point information with time tag CP56Time2a 										*/
#define M_DP_TB_1  31     /* double-point information with time tag CP56Time2a 										*/
#define M_ST_TB_1  32     /* step position information with time tag CP56Time2a 									*/
#define M_BO_TB_1  33     /* bitstring of 32 bit with time tag CP56Time2a 											*/
#define M_ME_TD_1  34     /* measured value, normalized value with time tag CP56Time2a 								*/
#define M_ME_TE_1  35     /* measured value, scaled value with time tag CP56Time2a 									*/
#define M_ME_TF_1  36     /* measured value, short floating point number with time tag CP56Time2a 					*/
#define M_IT_TB_1  37     /* integrated totals with time tag CP56Time2a 											*/
#define M_EP_TD_1  38     /* event of protection equipment with time tag CP56Time2a 								*/
#define M_EP_TE_1  39     /* packed start events of protection equipment with time tag CP56Time2a 					*/
#define M_EP_TF_1  40     /* packed output circuit information of protection equipment with time tag CP56Time2a 	*/
#define C_SC_NA_1  45     /* single command 																		*/
#define C_DC_NA_1  46     /* double command 																		*/
#define C_RC_NA_1  47     /* regulating step command 																*/
#define C_SE_NA_1  48     /* set point command, normalized value 													*/
#define C_SE_NB_1  49     /* set point command, scaled value 														*/
#define C_SE_NC_1  50     /* set point command, short floating point number 										*/
#define C_BO_NA_1  51     /* bitstring of 32 bits 																	*/
#define C_SC_TA_1  58     /* single command with time tag CP56Time2a 												*/
#define C_DC_TA_1  59     /* double command with time tag CP56Time2a 												*/
#define C_RC_TA_1  60     /* regulating step command with time tag CP56Time2a 										*/
#define C_SE_TA_1  61     /* set point command, normalized value with time tag CP56Time2a 							*/
#define C_SE_TB_1  62     /* set point command, scaled value with time tag CP56Time2a 								*/
#define C_SE_TC_1  63     /* set point command, short floating-point number with time tag CP56Time2a 				*/
#define C_BO_TA_1  64     /* bitstring of 32 bits with time tag CP56Time2a 											*/
#define M_EI_NA_1  70     /* end of initialization 																	*/
#define C_IC_NA_1  100    /* interrogation command 																	*/
#define C_CI_NA_1  101    /* counter interrogation command 															*/
#define C_RD_NA_1  102    /* read command 																			*/
#define C_CS_NA_1  103    /* clock synchronization command 															*/
#define C_RP_NA_1  105    /* reset process command 																	*/
#define C_TS_TA_1  107    /* test command with time tag CP56Time2a 													*/
#define P_ME_NA_1  110    /* parameter of measured value, normalized value 											*/
#define P_ME_NB_1  111    /* parameter of measured value, scaled value 												*/
#define P_ME_NC_1  112    /* parameter of measured value, short floating-point number 								*/
#define P_AC_NA_1  113    /* parameter activation 																	*/
#define F_FR_NA_1  120    /* file ready 																			*/
#define F_SR_NA_1  121    /* section ready 																			*/
#define F_SC_NA_1  122    /* call directory, select file, call file, call section 									*/
#define F_LS_NA_1  123    /* last section, last segment 															*/
#define F_AF_NA_1  124    /* ack file, ack section 																	*/
#define F_SG_NA_1  125    /* segment 																				*/
#define F_DR_TA_1  126    /* directory 																				*/
#define F_SC_NB_1  127 	  /* Query Log - Request archive file 														*/


int iec104_counter_type_S=0;
int iec104_counter_type_U=0;
int iec104_counter_type_I=0;
int tcp_counter=0;
int udp_counter=0;
int iec104_counter=0;
int testfr_act=0;
int testfr_con=0;
int startdt_con=0;
int startdt_act=0;
int stopdt_con=0;
int stopdt_act=0;

typedef struct {
	uint8_t  value;
	uint8_t  length;
} td_asdu_length;

static const td_asdu_length asdu_length [] = {
	{  M_SP_NA_1,	 1 },
	{  M_DP_NA_1,	 1 },
	{  M_ST_NA_1,	 2 },
	{  M_BO_NA_1,	 5 },
	{  M_ME_NA_1,	 3 },
	{  M_ME_NB_1,	 3 },
	{  M_ME_NC_1,	 5 },
	{  M_IT_NA_1,	 5 },
	{  M_PS_NA_1,	 5 },
	{  M_ME_ND_1,	 2 },
	{  M_SP_TB_1,	 8 },
	{  M_DP_TB_1,	 8 },
	{  M_ST_TB_1,	 9 },
	{  M_BO_TB_1,	12 },
	{  M_ME_TD_1,	10 },
	{  M_ME_TE_1,	10 },
	{  M_ME_TF_1,	12 },
	{  M_IT_TB_1,	12 },
	{  M_EP_TD_1,	10 },
	{  M_EP_TE_1,	11 },
	{  M_EP_TF_1,	11 },
	{  C_SC_NA_1,	 1 },
	{  C_DC_NA_1,	 1 },
	{  C_RC_NA_1,	 1 },
	{  C_SE_NA_1,	 3 },
	{  C_SE_NB_1,	 3 },
	{  C_SE_NC_1,	 5 },
	{  C_BO_NA_1,	 4 },
	{  C_SC_TA_1,	 8 },
	{  C_DC_TA_1,	 8 },
	{  C_RC_TA_1,	 8 },
	{  C_SE_TA_1,	10 },
	{  C_SE_TB_1,	10 },
	{  C_SE_TC_1,	12 },
	{  C_BO_TA_1,	11 },
	{  M_EI_NA_1,	 1 },
	{  C_IC_NA_1,	 1 },
	{  C_CI_NA_1,	 1 },
	{  C_RD_NA_1,	 0 },
	{  C_CS_NA_1,	 7 },
	{  C_RP_NA_1,	 1 },
	{  C_TS_TA_1,	 9 },
	{  P_ME_NA_1,	 3 },
	{  P_ME_NB_1,	 3 },
	{  P_ME_NC_1,	 5 },
	{  P_AC_NA_1,	 1 },
	{  F_FR_NA_1,	 6 },
	{  F_SR_NA_1,	 7 },
	{  F_SC_NA_1,	 4 },
	{  F_LS_NA_1,	 5 },
	{  F_AF_NA_1,	 4 },
	{  F_SG_NA_1,	 0 },
	{  F_DR_TA_1,	13 },
	{  F_SC_NB_1,	16 },
	{ 0, 0 }
};

int apdulength;
int ii=0;

int column=0, numeroi=100;


void analizar_paquete(const struct pcap_pkthdr *hdr, const uint8_t *pack);

void handleSignal(int nsignal);

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETH_ALEN]; 		/* Destination host address */
	u_char ether_shost[ETH_ALEN]; 		/* Source host address */		
	u_short ether_type; 				/* IP? ARP? RARP? etc */
};

struct sniff_virtualLan {
	uint16_t init;
	uint16_t Lan_type; 				/* IP? ARP? RARP? etc */
	uint16_t padding;
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;				/* version << 4 | header length >> 2 */
	u_char ip_tos;				/* type of service */
	u_short ip_len;				/* total length */
	u_short ip_id;				/* identification */
	u_short ip_off;				/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;				/* time to live */
	u_char ip_p;				/* protocol */
	u_short ip_sum;				/* checksum */
	u_char ip_src[IP_ALEN];
	u_char ip_dst[IP_ALEN]; 	/* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

	

	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

/* UDP header */

struct sniff_udp {
	u_short udp_sport;	/* source port */
	u_short udp_dport;	/* destination port */
	u_short udp_len;	/* length */
	u_short udp_sum;	/*checksum*/
};

/* IEC 60870-5-104 header */
struct sniff_104{
	uint8_t start;				/* START */
	uint8_t apdu_length;		/* Length of APDU headerm */
	uint8_t octet_1;			/* Octets for FORMAT */
	uint8_t octet_2;			/* Octets for FORMAT */
	uint8_t octet_3;			/* Octets for FORMAT */
	uint8_t octet_4;			/* Octets for FORMAT */
	uint8_t type;				/* Type identification */
	uint8_t sq_numIx; 			/* Structure qualifier 1 bit */ /* Number of objects */
	uint8_t causeTx;			/* Cause of transmission */
								/* Test 1 bit */
								/* Positive or Negative 1 bit*/
	uint8_t oa;					/* Originator address */
	uint16_t addr;				/* ASDU addres fields */
	
	
};

struct ioa{
	uint32_t ioa;				/* Information objects address fields */
};



///////////////////////////////////lista paquetes mal formados////////////////////////////////////////////////////

struct malformed_struc{
	uint8_t ipsrc[IP_ALEN];
	uint8_t ipdst[IP_ALEN];
	uint8_t counter;

	struct malformed_struc *next;

};

struct malformed_struc *head_m = NULL;
struct malformed_struc *curr_m = NULL;

struct malformed_struc* create_list_malformed(uint8_t ipsrc[IP_ALEN],uint8_t ipdst[IP_ALEN], uint8_t counter)
{	int i;
    //printf("\n creating list with headnode as [%d]\n",val);
    struct malformed_struc *ptr = (struct malformed_struc*)malloc(sizeof(struct malformed_struc));
    if(NULL == ptr)
    {
        printf("\n Node creation failed \n");
        return NULL;
    }
    ptr->ipsrc[0]=ipsrc[0];
    for (i = 1; i < IP_ALEN; i++) {
			ptr->ipsrc[i]=ipsrc[i];
	}
	ptr->ipdst[0]=ipdst[0];
    for (i = 1; i < IP_ALEN; i++) {
			ptr->ipdst[i]=ipdst[i];
	}
    ptr->counter = counter;
    ptr->next = NULL;

    head_m = curr_m = ptr;
    return ptr;
}

struct malformed_struc* add_to_list_malformed(uint8_t ipsrc[IP_ALEN], uint8_t ipdst[IP_ALEN], uint8_t counter, bool add_to_end)
{
	int i;
    if(NULL == head_m)
    {
        return (create_list_malformed(ipsrc,ipdst, counter));
    }

    
    struct malformed_struc *ptr = (struct malformed_struc*)malloc(sizeof(struct malformed_struc));
    if(NULL == ptr)
    {
        printf("\n Node creation failed \n");
        return NULL;
    }

    ptr->ipsrc[0]=ipsrc[0];
    for (i = 1; i < IP_ALEN; i++) {
			ptr->ipsrc[i]=ipsrc[i];
	}
	ptr->ipdst[0]=ipdst[0];
    for (i = 1; i < IP_ALEN; i++) {
			ptr->ipdst[i]=ipdst[i];
	}
    ptr->counter = counter;
    ptr->next = NULL;

    if(add_to_end)
    {
        curr_m->next = ptr;
        curr_m = ptr;
    }
    else
    {
        ptr->next = head_m;
        head_m = ptr;
    }
    return ptr;
}
int foundIT;
struct malformed_struc* search_in_list_malformed(uint8_t ipsrc[IP_ALEN],uint8_t ipdst[IP_ALEN], struct malformed_struc **prev)
{
    struct malformed_struc *ptr = head_m;
    struct malformed_struc *tmp = NULL;
    bool found = false;
    foundIT=0;


    while(ptr != NULL)
    {
        if(ptr->ipsrc[0] == ipsrc[0] && ptr->ipsrc[1] == ipsrc[1] && ptr->ipsrc[2] == ipsrc[2] && ptr->ipsrc[3] == ipsrc[3] && ptr->ipdst[0] == ipdst[0] && ptr->ipdst[1] == ipdst[1] && ptr->ipdst[2] == ipdst[2] && ptr->ipdst[3] == ipdst[3])
        {	
            found = true;
            struct malformed_struc *ptr_aux=ptr;
            //printf("first %d     ", ptr->counter);
            ptr_aux->counter = ptr->counter + 1;
            //printf("%d\n", ptr->counter);
            foundIT=1;
            break;
        }
        else
        {
            tmp = ptr;
            ptr = ptr->next;
        }
    }

    if(true == found)
    {
        if(prev)
            *prev = tmp;
        return ptr;
    }
    else
    {
        return NULL;
    }
}

void print_list_malformed(void)
{
    struct malformed_struc *ptr = head_m;
    int i;
    printf("Malformed: \n");
    printf(" IP origen \t IP destino   \t Cantidad   \n\n");
    // Si se quiere guardar en un archivo descomentar estas lineas   ////////////////////////////////////////////////////////////////////////////
    //FILE *f = fopen("Malformed.csv","w");

    while(ptr != NULL)
    {
        	
		printf(" %d", ptr->ipsrc[0]);
		for (i = 1; i < IP_ALEN-1; i++) {
			printf(".%d",ptr->ipsrc[i]);
		}
		printf(".%d",ptr->ipsrc[3]);

		//formato//			
		if(ptr->ipsrc[0]<100) {printf(" ");}
		if(ptr->ipsrc[0]<10) {printf(" ");}

		if(ptr->ipsrc[1]<100) {printf(" ");}
		if(ptr->ipsrc[1]<10) {printf(" ");}

		if(ptr->ipsrc[2]<100) {printf(" ");}
		if(ptr->ipsrc[2]<10) {printf(" ");}

		if(ptr->ipsrc[3]<100) {printf(" ");}
		if(ptr->ipsrc[3]<10) {printf(" ");}
		//formato//	

		printf(" %d", ptr->ipdst[0]);
		for (i = 1; i < IP_ALEN-1; i++) {
			printf(".%d",ptr->ipdst[i]);
		}
		printf(".%d",ptr->ipdst[3]);

		//formato//		
		if(ptr->ipdst[0]<100) {printf(" ");}
		if(ptr->ipdst[0]<10) {printf(" ");}

		if(ptr->ipdst[1]<100) {printf(" ");}
		if(ptr->ipdst[1]<10) {printf(" ");}

		if(ptr->ipdst[2]<100) {printf(" ");}
		if(ptr->ipdst[2]<10) {printf(" ");}

		if(ptr->ipdst[3]<100) {printf(" ");}
		if(ptr->ipdst[3]<10) {printf(" ");}
		//formato//
	
        printf(" [%d] \n",ptr->counter);

        // Si se quiere guardar en un archivo descomentar estas lineas   ////////////////////////////////////////////////////////////////////////////

    //  printf(" %f %%\n",(ptr->counter/(double)iec104_counter_type_I)*100 );
     	//fprintf(f,"%d.%d.%d.%d , %d , %d , %f \n",ptr->ipsrc[0], ptr->ipsrc[1], ptr->ipsrc[2], ptr->ipsrc[3], ptr->type, ptr->counter, (ptr->counter/(double)iec104_counter_type_I)*100 );

        ptr = ptr->next;
    }
   
    printf("\n");

    return;
}


///////////////////////////////////lista paquetes mal formados////////////////////////////////////////////////////

///////////////////////////////////key generator//////////////////////////////////////////////////////////////////

int key_generator(const char* s) {
    int key = 0;
    while (*s) {
        key = 31*key + (*s++);
    }
    return key;
}


///////////////////////////////////end of key generator///////////////////////////////////////////////////////////

///////////////////////////////////hash///////////////////////////////////////////////////////////////////////////
typedef struct DataItem {
   	uint8_t ipsrc[IP_ALEN];
	uint8_t type;
	uint8_t counter;
	struct DataItem* next;
}DataItem;

DataItem *hash[1000000];
int hashSize = 10000;

int search(int key, uint8_t ipsrc[IP_ALEN], uint8_t type){
	DataItem *n;
	for(n=hash[key]; n != NULL; n=n->next){
		if(n->ipsrc[0]==ipsrc[0] && n->ipsrc[1]==ipsrc[1] && n->ipsrc[2]==ipsrc[2] && n->ipsrc[3]==ipsrc[3] && n->type==type ){
			n->counter++;
			return 1;
		}
	}

	return -1;
}


void insert(int key,uint8_t ipsrc[IP_ALEN], uint8_t type, uint8_t counter ){
	DataItem *new_node, *n1;
	new_node=(DataItem*)malloc(sizeof(DataItem));
	
		new_node->ipsrc[0]=ipsrc[0];
    for (int i = 1; i < IP_ALEN; i++) {
			new_node->ipsrc[i]=ipsrc[i];
	}
	new_node->type=type;
  	new_node->counter=counter;
	new_node->next=NULL;
	//new_node->key=key;
	
	key=key%hashSize;
	if(hash[key] == NULL)
	{
		hash[key]=new_node;
	}
	else{
		for(n1=hash[key]; n1->next !=NULL; n1=n1->next);
		n1->next=new_node;
	}
}

void printlist(DataItem *n){

	DataItem *n1;
	for(n1=n; n1!=NULL; n1=n1->next){
		
		 printf(" %d", n1->ipsrc[0]);
		for (int j = 1; j < IP_ALEN-1; j++) {
			printf(".%d",n1->ipsrc[j]);
		}
		printf(".%d",n1->ipsrc[3]);
		
	//formato//	
	if(n1->ipsrc[0]<100) {printf(" ");}
	if(n1->ipsrc[0]<10) {printf(" ");}

	if(n1->ipsrc[1]<100) {printf(" ");}
	if(n1->ipsrc[1]<10) {printf(" ");}

	if(n1->ipsrc[2]<100) {printf(" ");}
	if(n1->ipsrc[2]<10) {printf(" ");}

	if(n1->ipsrc[3]<100) {printf(" ");}
	if(n1->ipsrc[3]<10) {printf(" ");}
	//formato//

	printf(" [%3d] \t",n1->type);
        printf(" [%d] \t\t",n1->counter);
        printf(" %f %%\n",(n1->counter/(double)iec104_counter_type_I)*100 );

printf("\n");
	}
	 
}

void printHashtable(){
	printf("\tIP  \tTipo\tCantidad         Porcentaje\n\n");
	for(int i=0; i<hashSize; i++){
		printlist(hash[i]);
	}
}


///////////////////////////////////end of hash////////////////////////////////////////////////////////////////////
int numero=0;
int wrong_master=0;
///////////////////////////////////hash   IP ///////////////////////////////////////////////////////////////////////////
typedef struct node {
   	uint8_t ipsrc[IP_ALEN];
	uint8_t ipdst[IP_ALEN];
	//int key
	struct node* next;
}node;

node *hashTable[1000000];
int hashTableSize = 10000;

void insert_IP(int key, uint8_t ipsrc[IP_ALEN], uint8_t ipdst[IP_ALEN]){
	node *new_node, *n1;
	new_node=(node*)malloc(sizeof(node));
	
		new_node->ipsrc[0]=ipsrc[0];
    for (int i = 1; i < IP_ALEN; i++) {
			new_node->ipsrc[i]=ipsrc[i];
	}
	new_node->ipdst[0]=ipdst[0];
    for (int i = 1; i < IP_ALEN; i++) {
			new_node->ipdst[i]=ipdst[i];
	}
	new_node->next=NULL;
	//new_node->key=key;
	
	key=key%hashTableSize;
	if(hashTable[key] == NULL)
	{
		hashTable[key]=new_node;
	}
	else{
		for(n1=hashTable[key]; n1->next !=NULL; n1=n1->next);
		n1->next=new_node;
	}
}

int searchNode(int key, uint8_t ipsrc[IP_ALEN], uint8_t ipdst[IP_ALEN]){
	node *n;
	for(n=hashTable[key]; n != NULL; n=n->next){
		if(n->ipsrc[0]==ipsrc[0] && n->ipsrc[1]==ipsrc[1] && n->ipsrc[2]==ipsrc[2] && n->ipsrc[3]==ipsrc[3] && n->ipdst[0]==ipdst[0] && n->ipdst[1]==ipdst[1] && n->ipdst[2]==ipdst[2] && n->ipdst[3]==ipdst[3]){
			return 1;
		}
		
		if((n->ipsrc[0]==ipsrc[0] && n->ipsrc[1]==ipsrc[1] && n->ipsrc[2]==ipsrc[2] && n->ipsrc[3]==ipsrc[3]) && (n->ipdst[0]!=ipdst[0] || n->ipdst[1]!=ipdst[1] || n->ipdst[2]!=ipdst[2] || n->ipdst[3]!=ipdst[3])){
			/*printf("src: %d.", n->ipsrc[0]);
			printf("%d.", n->ipsrc[1]);
			printf("%d.", n->ipsrc[2]);
			printf("%d\n", n->ipsrc[3]);
			printf("dst: %d.", n->ipdst[0]);
			printf("%d.", n->ipdst[1]);
			printf("%d.", n->ipdst[2]);
			printf("%d\n", n->ipdst[3]);*/
			printf("NEW ATTACK!. Slave IP have more than 1 master IP at packet %d.\n", numero);
			wrong_master++;
			return 0;
		}
	}
	return -1;
}


///////////////////////////////////end of hash IP////////////////////////////////////////////////////////////////////

pcap_t *descr = NULL;
uint64_t contador = 0;
uint8_t ipsrc_filter[IP_ALEN] = {NO_FILTER};
uint8_t ipdst_filter[IP_ALEN] = {NO_FILTER};
uint16_t sport_filter= NO_FILTER;
uint16_t dport_filter = NO_FILTER;


int attack=0;
int throughput=0;

void handleSignal(int nsignal)
{
	(void) nsignal; // indicamos al compilador que no nos importa que nsignal no se utilice

	printf("Control C pulsado (%"PRIu64" paquetes leidos)\n", contador);
	pcap_close(descr);
	exit(OK);
}



int main(int argc, char **argv)
{
	uint8_t *pack = NULL;
	struct pcap_pkthdr *hdr;

	char errbuf[PCAP_ERRBUF_SIZE];
	char entrada[256];
	int long_index = 0, retorno = 0;
	char opt;

	clock_t t; 
   	t = clock();

   	/*//creamos la tabla hash
   	dummyItem = (struct DataItem*) malloc(sizeof(struct DataItem));
   	dummyItem->ipsrc[0]=-1;
   	int i=0;
    for (i = 1; i < IP_ALEN; i++) {
			dummyItem->ipsrc[i]=-1;
	}
	dummyItem->type = -1;
	dummyItem->counter = -1;
   	dummyItem->key = -1;*/


	if (argc > 1) {
		if (strlen(argv[1]) < 256) {
			strcpy(entrada, argv[1]);
		}

	} else {
		printf("Ejecucion: %s <-f traza.pcap \n", argv[0]);
		exit(ERROR);
	}

	static struct option options[] = {
		{"f", required_argument, 0, 'f'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long_only(argc, argv, "f:i:1:2:3:4:5", options, &long_index)) != -1) {

		switch (opt) {

			case 'f' :
				if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
					printf("Ha seleccionado más de una fuente de datos\n");
					pcap_close(descr);
					exit(ERROR);
				}
				
				if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
					printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
					exit(ERROR);
				}

				break;

			
			case '?' :
			default:
				printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
				exit(ERROR);
				break;
		}
	}

	if (!descr) {
		printf("No selecciono ningún origen de paquetes.\n");
		return ERROR;
	}

	printf("\n\n");

	do {
		retorno = pcap_next_ex(descr, &hdr, (const u_char **)&pack);   //leer el trafico del archivo

		if (retorno == PACK_READ) { //Todo correcto
			contador++;
				 

			analizar_paquete(hdr, pack);

				
			
		}
	} while (retorno != TRACE_END);

	///////////////////////////////////////////Print resumen de análisis///////////////////////////////////////////

	printf("Se procesaron %"PRIu64" paquetes.\n\n", contador);
	pcap_close(descr);
	printf("Ataques: %d\n", attack);
	if (tcp_counter==numero){
		printf("Los cuales el 100%% de ellos fueron TCP: %d \n", tcp_counter);
	}
	else printf("Los cuales el %f %% de ellos fueron TCP: %d \n\n", tcp_counter/(double)numero*100, tcp_counter);

	if (udp_counter==numero){
		printf("Los cuales el 100%% de ellos fueron UDP: %d \n", udp_counter);
	}
	else printf("Los cuales el %f %% de ellos fueron UDP: %d \n\n", udp_counter/(double)numero*100, udp_counter); 

	printf("Los cuales el %f %% de ellos fueron IEC104: %d \n\n", iec104_counter/(double)numero*100, iec104_counter);

	printf("Los cuales el %f %% de ellos fueron paquetes I: %d \n\n", iec104_counter_type_I/(double)numero*100, iec104_counter_type_I);
 	printHashtable(); 
 	printf("Los cuales el %f %% de ellos fueron paquetes I: %d \n\n", iec104_counter_type_I/(double)numero*100, iec104_counter_type_I);
	printf("\n");
	printf("Los cuales el %f %% de ellos fueron paquetes S: %d \n", iec104_counter_type_S/(double)numero*100, iec104_counter_type_S);
	printf("\n");
	printf("Los cuales el %f %% de ellos fueron paquetes U: %d \n", iec104_counter_type_U/(double)numero*100, iec104_counter_type_U);
	printf("TESTFR  act: %d\n", testfr_act);
	printf("TESTFR  con: %d\n", testfr_con);
	printf("STARTDT act: %d\n", startdt_act);
	printf("STARTDT con: %d\n", startdt_con);
	printf("STOPDT  act: %d\n", stopdt_act);
	printf("STOPDT  con: %d\n", stopdt_con);
	printf("\n");
	
	printf("Los cuales el %f %% de ellos fueron IEC104: %d \n\n", iec104_counter/(double)numero*100, iec104_counter);
	printf("Ataques: %d\n\n", attack);
	print_list_malformed();
	printf("Maestro erróneo: %d\n", wrong_master);
	 t = clock() - t; 
	double time_taken = ((double)t)/CLOCKS_PER_SEC;
	printf("El programa ha tardado %f segundos en ejecutar.\n\n", time_taken); 
	//printf("%d\n", throughput);
	throughput=throughput/time_taken;
	printf("El throughput es de %d Bytes/segundo.\n\n", throughput); 

	//borrar tras solucionar
	//print_list_pack();
	return OK;
}


void analizar_paquete(const struct pcap_pkthdr *hdr, const uint8_t *pack)
{	
	uint8_t log_cabecera, data_offset, tcp_length;
	uint16_t prueba1=0,prueba2=0, aux2, aux16=0, portori_tcp, portdes_tcp;
	int type, protocolo, ret=0, Total_length, i = 0;;
	u_int size_ip, size_tcp;


	uint8_t ether_dhost[ETH_ALEN]; 		
	uint8_t ether_shost[ETH_ALEN]; 

	uint8_t version;
	uint8_t ip_ttl;
	uint8_t ip_src[IP_ALEN];
	uint8_t ip_dst[IP_ALEN];

	uint8_t start;

	int add=0;
	int key_IP;
	int hash;
	int hashfind;
	td_asdu_length *item;
	

	numero+=1;			
	
	const struct sniff_ethernet *ethernet;
	ethernet = (struct sniff_ethernet*)(pack);

	//printf("Direccion ETH destino= ");
	ether_dhost[0]=ethernet->ether_dhost[0];
	for (i = 1; i < ETH_ALEN; i++) {
		ether_dhost[i]=ethernet->ether_dhost[i];
	}

	//printf("Direccion ETH origen = ");
	ether_shost[0]=ethernet->ether_shost[0];
	for (i = 1; i < ETH_ALEN; i++) {
		ether_shost[i]=ethernet->ether_shost[i];
	}

	type=ethernet->ether_type;

	if (type==8){

		const struct sniff_ip *ip; /* The IP header */
		ip = (struct sniff_ip*)(pack + ETH_HLEN);

		size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			printf("NEW ATTACK. Invalid IP header length: %u bytes\n", size_ip);
			attack+=1;
			return;
		}

		version=(ip->ip_vhl>>4)&0xf;
		if (version!=4){
			printf("NEW ATTACK. Invalid version on packet %d\n", numero);
			attack+=1;
		}
		
		//printf("Longitud cabecera: ");
		log_cabecera=ip->ip_vhl&0xf;
		if(log_cabecera!=0x05){
			printf("NEW ATTACK. Invalid header length on packet %d\n", numero);
			attack+=1;
		}

		//printf("Longitud total: ");
		memcpy(&aux16,&ip->ip_len,sizeof(uint16_t));
		Total_length=ntohs(aux16);
		throughput=Total_length+ETH_HLEN+throughput;
		aux16=0;


	    //printf("Posición/Desplazamiento: ");      

		aux2=(ip->ip_off<<4)&0x1;
		memcpy(&prueba1, &aux2, sizeof(uint8_t));

		aux2=ip->ip_off&0xf;
		memcpy(&prueba2, &aux2 , sizeof(uint8_t));
		
		if (prueba1!=0){
			prueba1=255 + prueba2+ prueba1;
		} 

		//printf("Tiempo de vida: ");
		ip_ttl=ip->ip_ttl;
		if(ip_ttl==0){
			printf("NEW ATTACK. Invalid time to live on Packet %d\n", numero);
			attack+=1;
		}

		//printf("Protocolo: ");
		protocolo=ip->ip_p;
		

		//printf("Dirección origen: ");
		ip_src[0]=ip->ip_src[0];
		for (i = 1; i < IP_ALEN; i++) {
			ip_src[i]=ip->ip_src[i];
		}

		//printf("Dirección destino: ");
		ip_dst[0]=ip->ip_dst[0];
		for (i = 1; i < IP_ALEN; i++) {
			ip_dst[i]=ip->ip_dst[i];
		}

	}

	if (type==129){



		const struct sniff_virtualLan *lan; /* The IP header */
		lan = (struct sniff_virtualLan*)(pack + ETH_HLEN);


		type=lan->Lan_type;
		add=4;
		

		if(type==8){

			const struct sniff_ip *ip; /* The IP header */
			ip = (struct sniff_ip*)(pack + ETH_HLEN +add);

			size_ip = IP_HL(ip)*4;
			
			if (size_ip < 20) {
				printf("NEW ATTACK. Invalid IP header length: %u bytes on packet %d\n", size_ip, numero);
				attack+=1;
				return;
			}

			version=(ip->ip_vhl>>4)&0xf;
			if (version!=4){
				printf("NEW ATTACK. Invalid version on packet %d\n", numero);
				attack+=1;
			}
			
			//printf("Longitud cabecera: ");
			log_cabecera=ip->ip_vhl&0xf;
			if(log_cabecera!=0x05){
				printf("NEW ATTACK. Invalid header length on packet %d\n", numero);
				attack+=1;
			}	

			//printf("Longitud total: ");
			memcpy(&aux16,&ip->ip_len,sizeof(uint16_t));
			Total_length=ntohs(aux16);

			//Cálculo de throughput
			throughput=Total_length+ETH_HLEN+add+throughput;

			aux16=0;

		    //printf("Posición/Desplazamiento: ");      

			aux2=(ip->ip_off<<4)&0x1;
			memcpy(&prueba1, &aux2, sizeof(uint8_t));

			aux2=ip->ip_off&0xf;
			memcpy(&prueba2, &aux2 , sizeof(uint8_t));
			
			if (prueba1!=0){
				prueba1=255 + prueba2+ prueba1;
			}

			//printf("Tiempo de vida: ");
			ip_ttl=ip->ip_ttl;
			if(ip_ttl==0){
				printf("NEW ATTACK. Invalid time to live on Packet %d\n", numero);
				attack+=1;
			}

			//printf("Protocolo: ");
			protocolo=ip->ip_p;

			//printf("Dirección origen: ");
			ip_src[0]=ip->ip_src[0];
			for (i = 1; i < IP_ALEN; i++) {
				ip_src[i]=ip->ip_src[i];
			}


			//printf("Dirección destino: ");
			ip_dst[0]=ip->ip_dst[0];
			for (i = 1; i < IP_ALEN; i++) {
				ip_dst[i]=ip->ip_dst[i];
			}
		}

	}



	
	if (prueba2==0){

		///////////////////////////////////////////////////////////////TCP////////////////////////////////////////////////////////////////////
		if (protocolo==6){  // tcp

			tcp_counter+=1;

			const struct sniff_tcp *tcp; /* The TCP header */
			tcp = (struct sniff_tcp*)(pack + ETH_HLEN + add + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
				printf(" NEW ATTACK. Invalid TCP header length: %u bytes at packet %d\n", size_tcp, numero);
				attack+=1;
				return;
			}

			//printf("Puerto origen: ");
			memcpy(&aux16,&tcp->th_sport,sizeof(uint16_t));
			portori_tcp=ntohs(aux16);

			//printf("Puerto destino: ");
			memcpy(&aux16,&tcp->th_dport,sizeof(uint16_t));
			portdes_tcp=ntohs(aux16);

			data_offset = ((tcp->th_offx2 & 0xf0) >> 4);

			tcp_length=Total_length - (log_cabecera+data_offset) * 4;
		
			
			///////////////////////////////////////////////////////////////Iec 104////////////////////////////////////////////////////////////////
			if ((portori_tcp==2404 || portdes_tcp==2404) && tcp_length !=0){
				
				apdulength=0;

				while(1){
				        //Comprobación de IP esclavo 1 solo maestro//////////////
					if (portori_tcp==2404){
						key_IP=ip_src[0]+ip_src[1]+ip_src[2]+ip_src[3];

						hashfind=searchNode( key_IP, ip_src, ip_dst);

						if(hashfind == -1){
							insert_IP(key_IP, ip_src, ip_dst);
						} 
					}	
					////////////////////////////////////////////////////////
					const struct sniff_104 *iec104; /* The IEC104 header */
					if (apdulength==0){
						iec104 = (struct sniff_104*)(pack + ETH_HLEN + add  + size_ip + size_tcp );
					}
					else iec104 = (struct sniff_104*)(pack + ETH_HLEN + add  + size_ip + size_tcp +apdulength +0x02);

					start=iec104->start;

					if(start !=0x68){
						iec104 = (struct sniff_104*)(pack + ETH_HLEN + add  + size_ip + size_tcp +apdulength);

						if(start !=0x68){
							printf("NEW ATTACK!. Start field %x is not the expected 68 at packet %d\n", start, numero);
							attack+=1;
							return	;
						}
					}
					
					if(apdulength==0){
						apdulength=iec104->apdu_length;
					}
					else{
						apdulength=iec104->apdu_length + apdulength +0x02;
					}
					

				
					///////////////////////////////////////////////////////////////S-Format///////////////////////////////////////////////////////////////
					if((iec104->octet_1 & 0x03) == 0x1){    // S-Format
			
						iec104_counter_type_S+=1;
						

						if(iec104->apdu_length!=0x04){
							printf("NEW ATTACK!. Wrong Apdu length, it must be 4 instead of %d at packet %d \n", iec104->apdu_length, numero);
							attack+=1;
						}

						if ((size_ip + size_tcp +apdulength +0x02)>=Total_length){
							iec104_counter+=1;

							return;
						}

					}
					///////////////////////////////////////////////////////////////End of S-Format/////////////////////////////////////////////////////////

					///////////////////////////////////////////////////////////////U-Format///////////////////////////////////////////////////////////////
					if ((iec104->octet_1 & 0x03) == 0x3){   //U-Format
					
						iec104_counter_type_U+=1;
						int att=0;

						if(iec104->apdu_length!=0x04){
							printf("NEW ATTACK!. Wrong Apdu length, it must be 4 instead of %d at packet %d \n", iec104->apdu_length, numero);
							attack+=1;
						}
									

						if ((iec104->octet_1 & 0xC0) == 0x40)
						{
							testfr_act+=1;
							att=1;
						}
						if ((iec104->octet_1 & 0xC0) == 0x80)
						{
							testfr_con+=1;
							att=1;
						}

						if ((iec104->octet_1 & 0x30) == 0x20)
						{
							stopdt_con+=1;
							att=1;
						}
						if ((iec104->octet_1 & 0x30) == 0x10)
						{
							stopdt_act+=1;
							att=1;
						}

						if ((iec104->octet_1 & 0x0C) == 0x08)
						{
							startdt_con+=1;
							att=1; 
						}
						if ((iec104->octet_1 & 0x0C) == 0x04)
						{
							startdt_act+=1;
							att=1;
						}
						if (att==0) {
							printf("NEW ATTACK!. Wrong U-packet at packet %d\n", numero);
						}

						if ((size_ip + size_tcp +apdulength +0x02)>=Total_length){
							iec104_counter+=1;

							return;
						}
						
					}
					///////////////////////////////////////////////////////////////End of U-Format/////////////////////////////////////////////////////////

					///////////////////////////////////////////////////////////////I-Format///////////////////////////////////////////////////////////////
					if( (iec104->octet_1 & 0x03) == 0x0 || (iec104->octet_1 & 0x03) == 0x2){  
					
						iec104_counter_type_I+=1;
						int key;

						//tabla hash
						key=ip_src[0]+ip_src[1]+ip_src[2]+ip_src[3]+iec104->type;
						
						hash=search(key, ip_src,iec104->type);
						if(hash == -1){
							insert(key, ip_src,iec104->type,1);
						}

						//printf("Sequence: ");
						int sq;
						if(((iec104->sq_numIx >>4) & 0x8)==0x0){
						
							sq=0; //false
						}
						else sq=1; //true
						item = (td_asdu_length *)asdu_length;
 						while (item->value){
					    	if (item->value == iec104->type){
						      ret = item->length;
						      break;
						    }
					    item++;
						}	

						if(sq==0){
							if((ret+3)*(iec104->sq_numIx & 0x7F )+13 != iec104->apdu_length && (ret+3)*(iec104->sq_numIx & 0x7F )+8 != iec104->apdu_length && (ret+3)*(iec104->sq_numIx & 0x7F )+10 != iec104->apdu_length){
								
								printf("NEW ATTACK!. Malformed Packet. Objects size %d doesn't match with objects type %d at packet %d \n",((ret+3)*(iec104->sq_numIx & 0x7F )+8),iec104->apdu_length, numero);
								attack+=1;
								search_in_list_malformed(ip_src,ip_dst, NULL);
							        if(foundIT==0)
							        {
							           	add_to_list_malformed(ip_src,ip_dst,1,true);
							        }
							return;	
							}
						}else{
							if(((ret+3)+ret*((iec104->sq_numIx & 0x7F) -1 )+13) != iec104->apdu_length && ((ret+3)+ret*((iec104->sq_numIx & 0x7F) -1 )+8) != iec104->apdu_length && ((ret+3)+ret*((iec104->sq_numIx & 0x7F) -1 )+10) != iec104->apdu_length){
								
								printf("NEW ATTACK!. Malformed Packet. Objects size %d doesn't match with objects type %d at packet %d \n",((ret+3)*(iec104->sq_numIx & 0x7F )+8),iec104->apdu_length, numero);
								attack+=1;
								search_in_list_malformed(ip_src,ip_dst, NULL);
							        if(foundIT==0)
								{
							           	add_to_list_malformed(ip_src,ip_dst,1,true);
							        }
							return;								
							}
						}						

						if(iec104->type>127 || iec104->type==0){
							printf("NEW ATTACK!. Wrong Type identification %d. It is not defined at packet %d\n", iec104->type, numero);
							attack+=1;
						}
												
						if(portdes_tcp==2404 && ((iec104->type >= 45 && iec104->type <= 51) || (iec104->type >= 58 && iec104->type <= 64) || (iec104->type >= 100 && iec104->type <= 103) || iec104->type==103 || iec104->type==105 || iec104->type==107 || (iec104->type >= 110 && iec104->type <= 113) )){
							
						}else if(portdes_tcp==2404){
							printf("NEW ATTACK!. Wrong MASTER Type identification %d. at packet %d\n", iec104->type, numero);
								attack+=1;
						}

						if(portori_tcp==2404 && ((iec104->type < 16 && iec104->type % 2 == 1)  || iec104->type==20 || iec104->type==21 || (iec104->type >= 30 && iec104->type <= 40) || (iec104->type >= 45 && iec104->type <= 51) || (iec104->type >= 58 && iec104->type <= 64) || iec104->type==70 || iec104->type==100 || iec104->type==101 || iec104->type==103 || iec104->type==105 || iec104->type==107 || (iec104->type >= 110 && iec104->type <= 113))){
														
						}else if(portori_tcp==2404){

								printf("NEW ATTACK!. Wrong SLAVE Type identification %d. at packet %d\n", iec104->type, numero);
								attack+=1;
						}
	
						
						
						if(sq==0){
							if((iec104->type== 1 || iec104->type== 3 || iec104->type== 45 || iec104->type== 46 || iec104->type== 47 || iec104->type== 70 || iec104->type== 100 || iec104->type== 101 || iec104->type== 105 || iec104->type== 113) && (iec104->apdu_length!= (0x08 + ((iec104->sq_numIx & 0x7F) *4 )) && iec104->apdu_length!= (0x0a + ((iec104->sq_numIx & 0x7F) *4 )))){
								printf("NEW ATTACK!. Wrong Apdu length, it must be 14 instead of %d at packet %d\n", iec104->apdu_length, numero);
								attack+=1;
							}

						}else{
							if((iec104->type== 1 || iec104->type== 3 || iec104->type== 45 || iec104->type== 46 || iec104->type== 47 || iec104->type== 70 || iec104->type== 100 || iec104->type== 101 || iec104->type== 105 || iec104->type== 113) && (iec104->apdu_length!= (0x08 + (((iec104->sq_numIx & 0x7F)-1) +4 )) && iec104->apdu_length!= (0x0a + (((iec104->sq_numIx & 0x7F)-1) +4 )))){
								printf("NEW ATTACK!. Wrong Apdu length, it must be %d instead of %d at packet %d\n", iec104->apdu_length, (0x0a + ((iec104->sq_numIx & 0x7F) +4 )), numero);
								attack+=1;
							}

						}
						
						
						if ((iec104->sq_numIx & 0x7F) > 0x7F){    //0-127 defines no. of information objects or elements
							printf("NEW ATTACK!. Wrong Number of Objects: %d it is higher than 127 at packet %d\n", iec104->sq_numIx & 0x7F, numero);
							attack+=1;
						}
						
						if ((iec104->causeTx & 0x3f)> 0xFFFF){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d it is higher than 65535 at packet %d\n", iec104->causeTx & 0x3f, numero);
							attack+=1;
						}


						if(iec104->type==1 && (( iec104->causeTx & 0x3f)!= 2 && (iec104->causeTx & 0x3f)!= 3 && (iec104->causeTx & 0x3f)!= 5 && (iec104->causeTx & 0x3f)!= 11 && (iec104->causeTx & 0x3f)!= 20)){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==3 || iec104->type==5 || iec104->type==7 || iec104->type==9 || iec104->type==11 || iec104->type==13 || iec104->type==20 || iec104->type==36) && (( iec104->causeTx & 0x3f)!= 2 && (iec104->causeTx & 0x3f)!= 3 && (iec104->causeTx & 0x3f)!= 5 && (iec104->causeTx & 0x3f)!= 11 && ( iec104->causeTx & 0x3f)!= 12 && (iec104->causeTx & 0x3f)!= 20)){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if(iec104->type==15 && (( iec104->causeTx & 0x3f)!= 2 && (iec104->causeTx & 0x3f)!= 37 )){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if(iec104->type==21 && (( iec104->causeTx & 0x3f)!= 1 && (iec104->causeTx & 0x3f)!= 2 && ( iec104->causeTx & 0x3f)!= 3 && (iec104->causeTx & 0x3f)!= 5 && ( iec104->causeTx & 0x3f)!= 11 && (iec104->causeTx & 0x3f)!= 12  && (iec104->causeTx & 0x3f)!= 20)){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						//añadido la excepción del 20.
						if((iec104->type==30 || iec104->type==31) && (( iec104->causeTx & 0x3f)!= 3 && (iec104->causeTx & 0x3f)!= 5 && (iec104->causeTx & 0x3f)!= 11 && (iec104->causeTx & 0x3f)!= 12 && (iec104->causeTx & 0x3f)!= 20)){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}
						//añadido la excepción del 20.
						if((iec104->type==32) && (( iec104->causeTx & 0x3f)!= 2 && ( iec104->causeTx & 0x3f)!= 3 && (iec104->causeTx & 0x3f)!= 5 && (iec104->causeTx & 0x3f)!= 11 && (iec104->causeTx & 0x3f)!= 12 && (iec104->causeTx & 0x3f)!= 20 )){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}
						//añadido la excepción del 20.
						if((iec104->type==33 || iec104->type==34 || iec104->type==35) && (( iec104->causeTx & 0x3f)!= 3 && (iec104->causeTx & 0x3f)!= 5 && (iec104->causeTx & 0x3f)!= 20 )){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==37) && (( iec104->causeTx & 0x3f)!= 3 && ( iec104->causeTx & 0x3f)!= 37 )){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==38 || iec104->type==39 || iec104->type==40) && (( iec104->causeTx & 0x3f)!= 3 )){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==45 || iec104->type==46 || iec104->type==47 || iec104->type==48 || iec104->type==49 || iec104->type==50 || iec104->type==51 || iec104->type==100 || iec104->type==101) && (( iec104->causeTx & 0x3f)!= 6 && (iec104->causeTx & 0x3f)!= 7 && (iec104->causeTx & 0x3f)!= 8 && (iec104->causeTx & 0x3f)!= 9 && (iec104->causeTx & 0x3f)!= 10 && (iec104->causeTx & 0x3f)!= 44 && (iec104->causeTx & 0x3f)!= 45 && (iec104->causeTx & 0x3f)!= 46 && (iec104->causeTx & 0x3f)!= 47)){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}


						///////////////////////////////////////////////////////////////////////////  

						/*	En la lista de cause of transmission esta definida como:

							Code 	Cause of Transmission 					Abbreviation

							44   	type-Identification unknown 			uknown_type
							45 		cause unknown 							uknown_cause
							46 		ASDU address unknown					unknown_asdu_address
							47 		Information object address unknown 		unknown_object_address

						*/
						if((iec104->type==100 || iec104->type==101 || (iec104->type >= 45 && iec104->type <= 48) ) && ((( iec104->causeTx & 0x3f)== 45) || (( iec104->causeTx & 0x3f)== 46) || (( iec104->causeTx & 0x3f)== 47) || (( iec104->causeTx & 0x3f)== 48))){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;		       
						}

						///////////////////////////////////////////////////////////////////////////  

						if((iec104->type==70) && (( iec104->causeTx & 0x3f)!= 4 )){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==45 || iec104->type==46 || iec104->type==47 || iec104->type==48 || iec104->type==49 || iec104->type==50 || iec104->type==51) && (( iec104->causeTx & 0x3f)!= 6 && (iec104->causeTx & 0x3f)!= 7 && (iec104->causeTx & 0x3f)!= 8 && (iec104->causeTx & 0x3f)!= 9 && (iec104->causeTx & 0x3f)!= 10 && (iec104->causeTx & 0x3f)!= 44 && (iec104->causeTx & 0x3f)!= 45 && (iec104->causeTx & 0x3f)!= 46 && (iec104->causeTx & 0x3f)!= 47)){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==102) && (( iec104->causeTx & 0x3f)!= 5)){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==103) && (( iec104->causeTx & 0x3f)!= 3 && ( iec104->causeTx & 0x3f)!= 6 && ( iec104->causeTx & 0x3f)!= 7 && ( iec104->causeTx & 0x3f)!= 44 && ( iec104->causeTx & 0x3f)!= 45 && ( iec104->causeTx & 0x3f)!= 46 && ( iec104->causeTx & 0x3f)!= 47 )){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==105) && (( iec104->causeTx & 0x3f)!= 6 && ( iec104->causeTx & 0x3f)!= 7 && ( iec104->causeTx & 0x3f)!= 44 && ( iec104->causeTx & 0x3f)!= 45 && ( iec104->causeTx & 0x3f)!= 46 && ( iec104->causeTx & 0x3f)!= 47 )){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==110) && (( iec104->causeTx & 0x3f)!= 6 && ( iec104->causeTx & 0x3f)!= 7 && ( iec104->causeTx & 0x3f)!= 9 && ( iec104->causeTx & 0x3f)!= 10 && ( iec104->causeTx & 0x3f)!= 20 && ( iec104->causeTx & 0x3f)!= 44 && ( iec104->causeTx & 0x3f)!= 45 && ( iec104->causeTx & 0x3f)!= 46 && ( iec104->causeTx & 0x3f)!= 47 )){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==111 || iec104->type==112) && (( iec104->causeTx & 0x3f)!= 6 && ( iec104->causeTx & 0x3f)!= 7 && ( iec104->causeTx & 0x3f)!= 20 && ( iec104->causeTx & 0x3f)!= 44 && ( iec104->causeTx & 0x3f)!= 45 && ( iec104->causeTx & 0x3f)!= 46 && ( iec104->causeTx & 0x3f)!= 47 )){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==113) && (( iec104->causeTx & 0x3f)!= 6 && ( iec104->causeTx & 0x3f)!= 7 && ( iec104->causeTx & 0x3f)!= 9 && ( iec104->causeTx & 0x3f)!= 8 && ( iec104->causeTx & 0x3f)!= 44 && ( iec104->causeTx & 0x3f)!= 45 && ( iec104->causeTx & 0x3f)!= 46 && ( iec104->causeTx & 0x3f)!= 47 )){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==120 || iec104->type==121 || iec104->type==123 || iec104->type==124 || iec104->type==125) && (( iec104->causeTx & 0x3f)!= 13)){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==122) && (( iec104->causeTx & 0x3f)!= 5 && ( iec104->causeTx & 0x3f)!= 13)){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}

						if((iec104->type==126) && (( iec104->causeTx & 0x3f)!= 5 && ( iec104->causeTx & 0x3f)!= 3)){
							printf("NEW ATTACK!. Wrong Cause of Transmission: %d with type: %d at packet: %d \n",( iec104->causeTx & 0x3f),iec104->type, numero);
							attack+=1;
						}


 						

						for(i=0; i<(iec104->sq_numIx & 0x7F ); i++){
	
							const struct ioa *ioa_;
			            	ioa_ = (struct ioa*)(pack + ETH_HLEN  + add + size_ip + size_tcp +apdulength +0x02  -(ret+3)*((iec104->sq_numIx & 0x7F )-i));
			               	
						}
										
						if ((size_ip + size_tcp +apdulength +0x02)>=Total_length){
							iec104_counter+=1;

							return;
						}

					}

					///////////////////////////////////////////////////////////////End of I-Format/////////////////////////////////////////////////////////
				
				}

			
				
			}
			///////////////////////////////////////////////////////////////End of Iec 104/////////////////////////////////////////////////////////
				

		///////////////////////////////////////////////////////////////End of TCP/////////////////////////////////////////////////////////////

		}

		else {

			printf("NEW ATTACK. No TCP layer on packet %d \n", numero );
			attack+=1;
			
			if (protocolo==17){   // udp

				udp_counter+=1;

				const struct sniff_udp *udp; /* The UDP header */
				udp = (struct sniff_udp*)(pack + ETH_HLEN  + add + size_ip);

				//printf("Puerto origen: ");
				memcpy(&aux16,&udp->udp_sport,sizeof(uint16_t));
				//printf("%d", ntohs(aux16));

				//printf("\n\n");

				//printf("Puerto destino: ");
				memcpy(&aux16,&udp->udp_dport,sizeof(uint16_t));
				//printf("%d", ntohs(aux16));

				//printf("\n\n");

				//printf("Longitud: ");
				memcpy(&aux16,&udp->udp_len,sizeof(uint16_t));
				//printf("%d\n", ntohs(aux16));
				
			}

			else {
			printf("No es el protocolo esperado\n");
			}
		}
	}
	
	else {
		//printf("\n\n");

		//printf("El paquete IP leido no es el primer fragmento\n");
		//printf("\n\n");
	
	}

}


