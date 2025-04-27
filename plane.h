#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <semaphore.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>

#ifndef __SI__PLANE_H
#define __SI__PLANE_H

#define MAX_NUM_OF_SESS             				4   /* Num of APN(Session) per UE */
#define MAX_NUM_OF_BEARER           				4   /* Num of Bearer per Session */
#define MAX_NUM_OF_RULE             				4   /* Num of Rule per Session */
#define MAX_NUM_OF_PF               				16  /* Num of PacketFilter per Bearer */
#define MAX_NUM_OF_PACKET_BUFFER    				64  /* Num of PacketBuffer per UE */


typedef enum 
{
    PFCP_OBJ_BASE = 0,
    PFCP_OBJ_SESS_TYPE,
    PFCP_OBJ_PDR_TYPE,
    PFCP_OBJ_TOP,
} pfcp_object_type_e;

typedef struct pfcp_object_s 
{
    //lnode_t lnode;
    pfcp_object_type_e type;
} pfcp_object_t;

typedef struct pfcp_sess_s 	pfcp_sess_t;
typedef struct pfcp_pdr_s 	pfcp_pdr_t;
typedef struct pfcp_far_s 	pfcp_far_t;
typedef struct pfcp_urr_s 	pfcp_urr_t;
typedef struct pfcp_qer_s 	pfcp_qer_t;
typedef struct pfcp_bar_s 	pfcp_bar_t;

typedef struct pfcp_pdr_s 
{
    pfcp_object_t       	obj;
    uint32_t                index;

    struct {
        struct {
            int len;
            uint32_t key;
        } teid;
    } hash;

    uint8_t                 *id_node;      /* Pool-Node for ID */
    pfcp_pdr_id_t       	id;
    pfcp_precedence_t   	precedence;
    pfcp_interface_t    	src_if;

    union {
        char *apn;
        char *dnn;
    };

    pfcp_ue_ip_addr_t   	ue_ip_addr;
    int                     ue_ip_addr_len;

    pfcp_f_teid_t       	f_teid;
    int                     f_teid_len;

    int                    	chid;
    uint8_t                 choose_id;

    pfcp_outer_header_removal_t 	outer_header_removal;
    int                     		outer_header_removal_len;

    uint8_t                 qfi;

    pfcp_far_t          	*far;
    pfcp_urr_t          	*urr;
    pfcp_qer_t          	*qer;

    int                     num_of_flow;
    char                    *flow_description[MAX_NUM_OF_RULE];

    //ogs_list_t              rule_list;      /* Rule List */

    /* Related Context */
    //ogs_pfcp_sess_t         *sess;
    void                    *gnode;         /* For CP-Function */
} pfcp_pdr_t;


typedef struct pfcp_far_hash_f_teid_s {
    uint32_t teid;
    uint32_t addr[4];
} pfcp_far_hash_f_teid_t;

typedef struct pfcp_far_s {
    //ogs_lnode_t             lnode;

    struct {
        struct {
            int len;
            pfcp_far_hash_f_teid_t key;
        } f_teid;

        struct {
            int len;
            uint32_t key;
        } teid;
    } hash;

    uint8_t                 			*id_node;      /* Pool-Node for ID */
    pfcp_far_id_t       				id;
    pfcp_apply_action_t 				apply_action;
    pfcp_interface_t    				dst_if;
    pfcp_outer_header_creation_t 		outer_header_creation;
    int                     			outer_header_creation_len;

    pfcp_smreq_flags_t  				smreq_flags;

    uint32_t                			num_of_buffered_packet;
    //ogs_pkbuf_t             			*buffered_packet[MAX_NUM_OF_PACKET_BUFFER];

    struct {
        int prepared;
    } handover; /* Saved from N2-Handover Request Acknowledge */

    /* Related Context */
    pfcp_sess_t         	*sess;
    void                    *gnode;
} pfcp_far_t;


typedef struct pfcp_urr_s {
    //ogs_lnode_t             lnode;

    uint8_t                 *id_node;      /* Pool-Node for ID */
    pfcp_urr_id_t       	id;

    pfcp_sess_t         	*sess;
} pfcp_urr_t;


typedef struct pfcp_qer_s {
    //ogs_lnode_t             lnode;

    uint8_t                 *id_node;      /* Pool-Node for ID */
    pfcp_qer_id_t       	id;

    pfcp_gate_status_t  	gate_status;
    pfcp_bitrate_t      	mbr;
    pfcp_bitrate_t      	gbr;

    uint8_t                 qfi;

    pfcp_sess_t         	*sess;
} ogs_pfcp_qer_t;


typedef struct pfcp_bar_s {
    //ogs_lnode_t             lnode;

    uint8_t                 *id_node;      /* Pool-Node for ID */
    pfcp_bar_id_t       	id;
    pfcp_sess_t         	*sess;
	
} pfcp_bar_t;


typedef struct pfcp_subnet_s pfcp_subnet_t;
typedef struct pfcp_ue_ip_s {
    uint32_t        addr[4];
    uint8_t         static_ip;

    /* Related Context */
    pfcp_subnet_t    *subnet;
} pfcp_ue_ip_t;

#define MAX_IFNAME_LEN              					32

typedef struct pfcp_dev_s {
    //ogs_lnode_t     lnode;

    char            ifname[MAX_IFNAME_LEN];
    /*
	ogs_socket_t    fd;

    ogs_sockaddr_t  *link_local_addr;
    ogs_poll_t      *poll;
	*/
} ogs_pfcp_dev_t;



#endif



















