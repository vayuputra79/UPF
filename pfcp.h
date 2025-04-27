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

#ifndef __SI__PFCP_LIB2604_H
#define __SI__PFCP_LIB2604_H

#include "sirik_core.h"
#include "sirik_socket.h"


#define PFCP_HEADER_LEN 	16
#define PFCP_SEID_LEN   	8



#define TLV_MODE_T1_L1              		1
#define TLV_MODE_T1_L2              		2
#define TLV_MODE_T1_L2_I1           		3
#define TLV_MODE_T2_L2              		4



typedef struct tlv_s
{
    struct tlv_s *head;
    struct tlv_s *tail;
    struct tlv_s *next;

    struct tlv_s *parent;
    struct tlv_s *embedded;

    uint32_t type;
    uint32_t length;
    uint8_t instance;
    void *value;

    uint8_t buff_allocated;
    uint32_t buff_len;
    unsigned char *buff_ptr;
    unsigned char *buff;
} tlv_t;

#define tlv_type(pTlv) pTlv->type
#define tlv_length(pTlv) pTlv->length
#define tlv_instance(pTlv) pTlv->instance
#define tlv_value(pTlv) pTlv->value

tlv_t * tlv_add( tlv_t * head, uint32_t type, uint32_t length, uint8_t instance, void * value);
tlv_t * tlv_copy( void * buff, uint32_t buff_len, uint32_t type, uint32_t length, uint8_t instance, void * value);
tlv_t * tlv_embed( tlv_t * parent, uint32_t type, uint32_t length, uint8_t instance, void *value);
uint32_t tlv_render( tlv_t *root, uint8_t * data, uint32_t length, uint8_t mode);

tlv_t * tlv_parse_block( uint32_t length, void *data, uint8_t mode);
tlv_t * tlv_parse_embedded_block( tlv_t *tlv, uint8_t mode);		

tlv_t * tlv_find( tlv_t *root, uint32_t type);
tlv_t * tlv_find_root( tlv_t *tlv);
uint32_t tlv_calc_length( tlv_t *tlv, uint8_t mode);
uint32_t tlv_calc_count( tlv_t *tlv);
uint8_t tlv_value_8( tlv_t *tlv);
uint16_t tlv_value_16( tlv_t *tlv);
uint32_t tlv_value_32( tlv_t *tlv);

#define TLV_MAX_HEADROOM 16
#define TLV_VARIABLE_LEN 0
#define TLV_MAX_MORE 8
#define TLV_1_OR_MORE(__v) __v[TLV_MAX_MORE]

#define TLV_MAX_CHILD_DESC 128

typedef enum 
{
    TLV_UINT8,
    TLV_UINT16,
    TLV_UINT24,
    TLV_UINT32,
    TLV_INT8,
    TLV_INT16,
    TLV_INT24,
    TLV_INT32,
    TLV_FIXED_STR,
    TLV_VAR_STR,
    TLV_NULL,
    TLV_MORE,
    TLV_COMPOUND,
    TLV_MESSAGE,
} tlv_type_e;

typedef struct tlv_desc_s 
{
    tlv_type_e ctype;
    const char *name;
    uint16_t type;
    uint16_t length;
    uint8_t  instance;
    uint16_t vsize;
    void *child_descs[TLV_MAX_CHILD_DESC];
} tlv_desc_t;



typedef uint64_t tlv_presence_t;


typedef struct tlv_uint8_s {
    tlv_presence_t presence;
    uint8_t u8;
} tlv_uint8_t;


typedef struct tlv_uint16_s {
    tlv_presence_t presence;
    uint16_t u16;
} tlv_uint16_t;


typedef struct tlv_uint24_s {
    tlv_presence_t presence;
    uint32_t u24;
} tlv_uint24_t;


typedef struct tlv_uint32_s {
    tlv_presence_t presence;
    uint32_t u32;
} tlv_uint32_t;


typedef struct tlv_int8_s {
    tlv_presence_t presence;
    int8_t i8;
} tlv_int8_t;


typedef struct tlv_int16_s {
    tlv_presence_t presence;
    int16_t i16;
} tlv_int16_t;


typedef struct tlv_int24_s {
    tlv_presence_t presence;
    int32_t i24; 
} tlv_int24_t;


typedef struct tlv_int32_s {
    tlv_presence_t presence;
    int32_t i32;
} tlv_int32_t;

typedef struct tlv_octet_s {
    tlv_presence_t presence;
    void *data;
    uint32_t len;
} tlv_octet_t;


typedef struct tlv_null_s {
    tlv_presence_t presence;
} tlv_null_t;
























#define PFCP_VERSION                                    	1


typedef uint16_t pfcp_pdr_id_t;
typedef uint32_t pfcp_far_id_t;
typedef uint32_t pfcp_urr_id_t;
typedef uint32_t pfcp_qer_id_t;
typedef uint8_t  pfcp_bar_id_t;


#define PFCP_CAUSE_REQUEST_ACCEPTED                     	1
#define PFCP_CAUSE_REQUEST_REJECTED                     	64
#define PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND            	65
#define PFCP_CAUSE_MANDATORY_IE_MISSING                 	66
#define PFCP_CAUSE_CONDITIONAL_IE_MISSING               	67
#define PFCP_CAUSE_INVALID_LENGTH                       	68
#define PFCP_CAUSE_MANDATORY_IE_INCORRECT               	69
#define PFCP_CAUSE_INVALID_FORWARDING_POLICY            	70
#define PFCP_CAUSE_INVALID_F_TEID_ALLOCATION_OPTION     	71
#define PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION      	72
#define PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE   	73
#define PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION            	74
#define PFCP_CAUSE_NO_RESOURCES_AVAILABLE               	75
#define PFCP_CAUSE_SERVICE_NOT_SUPPORTED                	76
#define PFCP_CAUSE_SYSTEM_FAILURE                       	77


typedef uint32_t pfcp_precedence_t;

#define PFCP_INTERFACE_ACCESS                           	0
#define PFCP_INTERFACE_CORE                             	1
#define PFCP_INTERFACE_SGI_N6_LAN                       	2
#define PFCP_INTERFACE_CP_FUNCTION                      	3
#define PFCP_INTERFACE_LI_FUNCTION                      	4
#define PFCP_INTERFACE_UNKNOWN                          	0xff
typedef uint8_t pfcp_interface_t;


typedef struct pfcp_up_function_features_s {
    union {
        struct {
			uint8_t treu:1;
			uint8_t heeu:1;
			uint8_t pfdm:1;
			uint8_t ftup:1;
			uint8_t trst:1;
			uint8_t dldb:1;
			uint8_t ddnd:1;
			uint8_t bucp:1;
		};
		uint8_t octet5;
	};
    union {
        struct {	
			uint8_t epfar:1;
			uint8_t pfde:1;
			uint8_t frrt:1;
			uint8_t trace:1;
			uint8_t quoac:1;
			uint8_t udbc:1;
			uint8_t pdiu:1;
			uint8_t empu:1;
		};
		uint8_t octet6;
	};
	union {
        struct {
			uint8_t gcom:1;
			uint8_t bundl:1;
			uint8_t mte:1;
			uint8_t mnop:1;
			uint8_t sset:1;
			uint8_t ueip:1;
			uint8_t adpdp:1;
			uint8_t dpdra:1;
		};
        uint8_t octet7;
    };
	union {
        struct {
			uint8_t mptcp:1;
			uint8_t tscu:1;
			uint8_t ip6pl:1;
			uint8_t iptv:1;
			uint8_t norp:1;
			uint8_t vtime:1;
			uint8_t rttl:1;
			uint8_t mpas:1;
		};
		uint8_t octet8;
	};
    union {
        struct {
			uint8_t rds:1;
			uint8_t ddds:1;
			uint8_t ethar:1;
			uint8_t ciot:1;
			uint8_t mt_edt:1;
			uint8_t gpqm:1;
			uint8_t qfqm:1;
			uint8_t atsss_ll:1;
		};
        uint8_t octet9;
    };
	union {
        struct {
			uint8_t reserved:7;
			uint8_t rttwp:1;
		};
		uint8_t octet10;
	};
} __attribute__ ((packed)) pfcp_up_function_features_t;




#define PFCP_APPLY_ACTION_DROP                          	1
#define PFCP_APPLY_ACTION_FORW                          	2
#define PFCP_APPLY_ACTION_BUFF                          	4
#define PFCP_APPLY_ACTION_NOCP                          	8
#define PFCP_APPLY_ACTION_DUPL                          	16
typedef uint8_t  pfcp_apply_action_t;


typedef struct pfcp_cp_function_features_s {
    union {
        struct {
			uint8_t uiaur:1;
			uint8_t apdr:1;
			uint8_t mpas:1;
			uint8_t bundl:1;
			uint8_t sset:1;
			uint8_t epfar:1;
			uint8_t ovrl:1;
			uint8_t load:1;
		};
		uint8_t octet5;
	};
} __attribute__ ((packed)) pfcp_cp_function_features_t;


typedef struct pfcp_outer_header_removal_s {
#define PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IPV4         		0
#define PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IPV6         		1
#define PFCP_OUTER_HEADER_REMOVAL_UDP_IPV4              		2
#define PFCP_OUTER_HEADER_REMOVAL_UDP_IPV6              		3
#define PFCP_OUTER_HEADER_REMOVAL_IPV4                  		4
#define PFCP_OUTER_HEADER_REMOVAL_IPV6                  		5
#define PFCP_OUTER_HEADER_REMOVAL_GTPU_UDP_IP           		6
#define PFCP_OUTER_HEADER_REMOVAL_VLAN_STAG             		7
#define PFCP_OUTER_HEADER_REMOVAL_SLAN_CTAG             		8
    uint8_t description;

#define PFCP_PDU_SESSION_CONTAINER_TO_BE_DELETED        		1
    uint8_t gtpu_extheader_deletion;
} pfcp_outer_header_removal_t;

#define MAX_PCO_LEN                 							251
#define MAX_FQDN_LEN                							256


#define IPV4_LEN                        						4
#define IPV6_LEN                        						16
#define IPV6_DEFAULT_PREFIX_LEN         						64
#define IPV4V6_LEN                      						20

#define PFCP_NODE_ID_IPV4   									0
#define PFCP_NODE_ID_IPV6   									1
#define PFCP_NODE_ID_FQDN   									2

typedef struct pfcp_node_id_s 
{
	uint8_t     spare:4;
    uint8_t     type:4;
	
    union {
        uint32_t addr;
        uint8_t addr6[IPV6_LEN];
        char fqdn[MAX_FQDN_LEN];
    };
} __attribute__ ((packed)) pfcp_node_id_t;


typedef struct pfcp_f_seid_s {
	
	struct {
		uint8_t     ipv6:1;
		uint8_t     ipv4:1;
		uint8_t     spare:6;
	};
    uint64_t    seid;
    union {
        uint32_t addr;
        uint8_t addr6[IPV6_LEN];
        struct {
            uint32_t addr;
            uint8_t addr6[IPV6_LEN];
        } both;
    };
} __attribute__ ((packed)) pfcp_f_seid_t;



typedef struct pfcp_f_teid_s {
	uint8_t     spare1:4;
    uint8_t     chid:1;
    uint8_t     ch:1;
    uint8_t     ipv6:1;
    uint8_t     ipv4:1;
    union {
        struct {
			uint8_t choose_id;
            uint8_t spare2;
            uint8_t spare3;
            uint8_t spare4;
        };
        struct {
            uint32_t teid;
            union {
                uint32_t addr;
                uint8_t addr6[IPV6_LEN];
                struct {
                    uint32_t addr;
                    uint8_t addr6[IPV6_LEN];
                } both;
            };
        };
    };
} __attribute__ ((packed)) pfcp_f_teid_t;



typedef struct pfcp_ue_ip_addr_s 
{
#define PFCP_UE_IP_SRC     0
#define PFCP_UE_IP_DST     1
    uint8_t     ipv6:1;
    uint8_t     ipv4:1;
    uint8_t     sd:1;
    uint8_t     ipv6d:1;
    uint8_t     chv4:1;
    uint8_t     chv6:1;
    uint8_t     ip6pl:1;	
	uint8_t     spare:1;	
    union {
        uint32_t addr;
        uint8_t addr6[IPV6_LEN];
        struct {
            uint32_t addr;
            uint8_t addr6[IPV6_LEN];
        } both;
    };
} __attribute__ ((packed)) pfcp_ue_ip_addr_t;



typedef struct pfcp_outer_header_creation_s {
	uint8_t     stag:1;
    uint8_t     ctag:1;
    uint8_t     ip6:1;
    uint8_t     ip4:1;
    uint8_t     udp6:1;
    uint8_t     udp4:1;
    uint8_t     gtpu6:1;
    uint8_t     gtpu4:1;
    uint8_t     spare;
    uint32_t    teid;
    union {
        uint32_t addr;
        uint8_t addr6[IPV6_LEN];
        struct {
            uint32_t addr;
            uint8_t addr6[IPV6_LEN];
        } both;
    };
} __attribute__ ((packed)) pfcp_outer_header_creation_t;





typedef struct pfcp_sdf_filter_s {
    union {
        struct {
			uint8_t     spare1:3;
			uint8_t     bid:1;
			uint8_t     fl:1;
			uint8_t     spi:1;
			uint8_t     ttc:1;
			uint8_t     fd:1;
        };
        uint8_t flags;
    };

    uint8_t     spare2;
    uint16_t    flow_description_len;
    char        *flow_description;
    uint16_t    tos_traffic_class;
    uint32_t    security_parameter_index;
    uint32_t    flow_label;
    uint32_t    sdf_filter_id;
} __attribute__ ((packed)) pfcp_sdf_filter_t;



#define PFCP_BITRATE_LEN 10
typedef struct pfcp_bitrate_s {
    uint64_t    uplink;
    uint64_t    downlink;
} __attribute__ ((packed)) pfcp_bitrate_t;


#define PFCP_GATE_OPEN 0
#define PFCP_GATE_CLOSE 1
typedef struct pfcp_gate_status_s {
    union {
        struct {
			uint8_t     spare:4;
			uint8_t     uplink:2;
			uint8_t     downlink:2;
        };
        uint8_t value;
    };
} __attribute__ ((packed)) pfcp_gate_status_t;



typedef struct pfcp_report_type_s {
    union {
        struct {
			uint8_t     spare:4;
			uint8_t     user_plane_inactivity_report:1;
			uint8_t     error_indication_report:1;
			uint8_t     usage_report:1;
			uint8_t     downlink_data_report:1;
        };
        uint8_t value;
    };
} __attribute__ ((packed)) pfcp_report_type_t;


typedef struct pfcp_downlink_data_service_information_s {
    struct {
		uint8_t     spare:6;
		uint8_t     qfii:1;
		uint8_t     ppi:1;
    };
    union {
        uint8_t paging_policy_indication_value;
        uint8_t qfi;
        struct {
            uint8_t paging_policy_indication_value;
            uint8_t qfi;
        } both;
    };
} __attribute__ ((packed)) pfcp_downlink_data_service_information_t;


typedef struct pfcp_smreq_flags_s {
    union {
        struct {
			uint8_t     spare:5;
			uint8_t     query_all_urrs:1;
			uint8_t     send_end_marker_packets:1;
			uint8_t     drop_buffered_packets:1;
        };
        uint8_t value;
    };
} __attribute__ ((packed)) pfcp_smreq_flags_t;


#pragma pack(4)
typedef struct pfcp_user_plane_report_s {
    pfcp_report_type_t type;
    struct {
        uint8_t pdr_id;
        uint8_t paging_policy_indication_value;
        uint8_t qfi;
    } downlink_data;
    struct {
        pfcp_f_teid_t remote_f_teid;
        int remote_f_teid_len;
    } error_indication;
} pfcp_user_plane_report_t;


#define PFCP_NODE_TYPE__GATWEAY								1
#define PFCP_NODE_TYPE__USERPLANE							2


#pragma pack(4)
typedef struct __si_pfcp_node
{
	struct __si_pfcp_node * Next;
	
	int port;
	int ipversion;
	char address[50];
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	uint32_t upfAccesIP;  
	

	int isAssociationStarted;		
	
	int nodeType;
	int id;
	
	struct timeval lastheartbeatsent;
	int pending_heartbeat_response;
	
	struct timeval lastmsgsent;
	struct timeval lastmsg;
	int heartBeatStatus;
	
	SI_PowerTable * sessionTable;
	SI_PowerTable * teidTable;
	
} __si_pfcp_node_t;


#pragma pack(4)
typedef struct __si_pfcp
{
	int type;
	int port;
	
	char networkInstance[50];
	char address[50];
	int ipversion;
	SI_Socket * serverSocket;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	
	int nodeIdType;
	char nodeIdValue[120];	
	int hearbeatInterval;
	
	__si_pfcp_node_t * nodeHead;
	__si_pfcp_node_t * nodeCurrent;
	pthread_mutex_t nodeLock;
	int nodeCount;
	
	void * fsmThreadsPtr;
	int FsmThreadCount;
	
	void * pfcpMsgQueue;
	
	uint32_t seqNo;
	pthread_mutex_t seqLock;

} __si_pfcp_t;


uint32_t __si_pfcp__get_seqno();
int __si_pfcp__node_ipversion();
struct sockaddr_in 	* __si_pfcp__getIPv4_addr();
struct sockaddr_in6 * __si_pfcp__getIPv6_addr();

void __si_pfcp__initalize( int type, int port, int ipver, char * address, int nodeIdType, char * nodeIdValue);
__si_pfcp_node_t * __si_pfcp__add_upf( u_char * ipaddress, int ipv, int port);
void __si_pfcp__set_accessip( u_char * ipaddress, __si_pfcp_node_t * node);
uint32_t __si_pfcp__get_accessip( __si_pfcp_node_t * node);

__si_pfcp_node_t * __si_pfcp__get_upf();

__si_pfcp_node_t * __si_pfcp__find_node_by_ip( u_char * ip, int ipv, int port, int add);
int __si_pfcp__send_msg( __si_pfcp_node_t * node, __si_buff_t * pmsg);

typedef struct pfcp_message_s pfcp_message_t;

typedef void (*fp_onpfcp_msg) ( pfcp_message_t * pfcp_request, __si_pfcp_node_t * pNode, uint32_t seqNo, uint64_t SEID);
void __si_pfcp__setOnPfcpMsg( fp_onpfcp_msg fp);

__si_pfcp_node_t * __si_pfcp__get_root_node();
__si_pfcp_node_t * __si_pfcp__get_next_node( __si_pfcp_node_t * node);
void __si_pfcp__set_ipv4_addr( pfcp_node_id_t * node);







typedef struct pfcp_header_s 
{
    union 
	{
        struct 
		{
			uint8_t version:3;
            uint8_t spare1:3;
            uint8_t mp:1;
            uint8_t seid_presence:1;
        };
        uint8_t flags;
    };
    uint8_t type;
    uint16_t length;
	uint64_t seid;
    uint32_t sqn;
} __attribute__ ((packed)) pfcp_header_t;


#define PFCP_HEARTBEAT_REQUEST_TYPE 										1
#define PFCP_HEARTBEAT_RESPONSE_TYPE 										2
#define PFCP_PFD_MANAGEMENT_REQUEST_TYPE 									3
#define PFCP_PFD_MANAGEMENT_RESPONSE_TYPE 									4
#define PFCP_ASSOCIATION_SETUP_REQUEST_TYPE 								5
#define PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE 								6
#define PFCP_ASSOCIATION_UPDATE_REQUEST_TYPE 								7
#define PFCP_ASSOCIATION_UPDATE_RESPONSE_TYPE 								8
#define PFCP_ASSOCIATION_RELEASE_REQUEST_TYPE 								9
#define PFCP_ASSOCIATION_RELEASE_RESPONSE_TYPE 								10
#define PFCP_VERSION_NOT_SUPPORTED_RESPONSE_TYPE 							11
#define PFCP_NODE_REPORT_REQUEST_TYPE 										12
#define PFCP_NODE_REPORT_RESPONSE_TYPE 										13
#define PFCP_SESSION_SET_DELETION_REQUEST_TYPE 								14
#define PFCP_SESSION_SET_DELETION_RESPONSE_TYPE 							15
#define PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE 							50
#define PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE 							51
#define PFCP_SESSION_MODIFICATION_REQUEST_TYPE 								52
#define PFCP_SESSION_MODIFICATION_RESPONSE_TYPE 							53
#define PFCP_SESSION_DELETION_REQUEST_TYPE 									54
#define PFCP_SESSION_DELETION_RESPONSE_TYPE 								55
#define PFCP_SESSION_REPORT_REQUEST_TYPE 									56
#define PFCP_SESSION_REPORT_RESPONSE_TYPE 									57

#define PFCP_CREATE_PDR_TYPE 												1
#define PFCP_PDI_TYPE 														2
#define PFCP_CREATE_FAR_TYPE 												3
#define PFCP_FORWARDING_PARAMETERS_TYPE 									4
#define PFCP_DUPLICATING_PARAMETERS_TYPE 									5
#define PFCP_CREATE_URR_TYPE 												6
#define PFCP_CREATE_QER_TYPE 												7
#define PFCP_CREATED_PDR_TYPE 												8
#define PFCP_UPDATE_PDR_TYPE 												9
#define PFCP_UPDATE_FAR_TYPE 												10
#define PFCP_UPDATE_FORWARDING_PARAMETERS_TYPE 								11
#define PFCP_UPDATE_BAR_PFCP_SESSION_REPORT_RESPONSE_TYPE 					12
#define PFCP_UPDATE_URR_TYPE 												13
#define PFCP_UPDATE_QER_TYPE 												14
#define PFCP_REMOVE_PDR_TYPE 												15
#define PFCP_REMOVE_FAR_TYPE 												16
#define PFCP_REMOVE_URR_TYPE 												17
#define PFCP_REMOVE_QER_TYPE 												18
#define PFCP_CAUSE_TYPE 													19
#define PFCP_SOURCE_INTERFACE_TYPE 											20
#define PFCP_F_TEID_TYPE 													21
#define PFCP_NETWORK_INSTANCE_TYPE 											22
#define PFCP_SDF_FILTER_TYPE 												23
#define PFCP_APPLICATION_ID_TYPE 											24
#define PFCP_GATE_STATUS_TYPE 												25
#define PFCP_MBR_TYPE 														26
#define PFCP_GBR_TYPE 														27
#define PFCP_QER_CORRELATION_ID_TYPE 										28
#define PFCP_PRECEDENCE_TYPE 												29
#define PFCP_TRANSPORT_LEVEL_MARKING_TYPE 									30
#define PFCP_VOLUME_THRESHOLD_TYPE 											31
#define PFCP_TIME_THRESHOLD_TYPE 											32
#define PFCP_MONITORING_TIME_TYPE 											33
#define PFCP_SUBSEQUENT_VOLUME_THRESHOLD_TYPE 								34
#define PFCP_SUBSEQUENT_TIME_THRESHOLD_TYPE 								35
#define PFCP_INACTIVITY_DETECTION_TIME_TYPE 								36
#define PFCP_REPORTING_TRIGGERS_TYPE 										37
#define PFCP_REDIRECT_INFORMATION_TYPE 										38
#define PFCP_REPORT_TYPE_TYPE 												39
#define PFCP_OFFENDING_IE_TYPE 												40
#define PFCP_FORWARDING_POLICY_TYPE 										41
#define PFCP_DESTINATION_INTERFACE_TYPE 									42
#define PFCP_UP_FUNCTION_FEATURES_TYPE 										43
#define PFCP_APPLY_ACTION_TYPE 												44
#define PFCP_DOWNLINK_DATA_SERVICE_INFORMATION_TYPE 						45
#define PFCP_DOWNLINK_DATA_NOTIFICATION_DELAY_TYPE 							46
#define PFCP_DL_BUFFERING_DURATION_TYPE 									47
#define PFCP_DL_BUFFERING_SUGGESTED_PACKET_COUNT_TYPE 						48
#define PFCP_PFCPSMREQ_FLAGS_TYPE 											49
#define PFCP_PFCPSRRSP_FLAGS_TYPE 											50
#define PFCP_LOAD_CONTROL_INFORMATION_TYPE 									51
#define PFCP_SEQUENCE_NUMBER_TYPE 											52
#define PFCP_METRIC_TYPE 													53
#define PFCP_OVERLOAD_CONTROL_INFORMATION_TYPE 								54
#define PFCP_TIMER_TYPE 													55
#define PFCP_PDR_ID_TYPE 													56
#define PFCP_F_SEID_TYPE 													57
#define PFCP_APPLICATION_ID_S_PFDS_TYPE 									58
#define PFCP_PFD_CONTEXT_TYPE 												59
#define PFCP_NODE_ID_TYPE 													60
#define PFCP_PFD_CONTENTS_TYPE 												61
#define PFCP_MEASUREMENT_METHOD_TYPE 										62
#define PFCP_USAGE_REPORT_TRIGGER_TYPE 										63
#define PFCP_MEASUREMENT_PERIOD_TYPE 										64
#define PFCP_FQ_CSID_TYPE 													65
#define PFCP_VOLUME_MEASUREMENT_TYPE 										66
#define PFCP_DURATION_MEASUREMENT_TYPE 										67
#define PFCP_APPLICATION_DETECTION_INFORMATION_TYPE 						68
#define PFCP_TIME_OF_FIRST_PACKET_TYPE 										69
#define PFCP_TIME_OF_LAST_PACKET_TYPE 										70
#define PFCP_QUOTA_HOLDING_TIME_TYPE 										71
#define PFCP_DROPPED_DL_TRAFFIC_THRESHOLD_TYPE 								72
#define PFCP_VOLUME_QUOTA_TYPE 												73
#define PFCP_TIME_QUOTA_TYPE 												74
#define PFCP_START_TIME_TYPE 												75
#define PFCP_END_TIME_TYPE 													76
#define PFCP_QUERY_URR_TYPE 												77
#define PFCP_USAGE_REPORT_SESSION_MODIFICATION_RESPONSE_TYPE 				78
#define PFCP_USAGE_REPORT_SESSION_DELETION_RESPONSE_TYPE 					79
#define PFCP_USAGE_REPORT_SESSION_REPORT_REQUEST_TYPE 						80
#define PFCP_URR_ID_TYPE 													81
#define PFCP_LINKED_URR_ID_TYPE 											82
#define PFCP_DOWNLINK_DATA_REPORT_TYPE 										83
#define PFCP_OUTER_HEADER_CREATION_TYPE 									84
#define PFCP_CREATE_BAR_TYPE 												85
#define PFCP_UPDATE_BAR_SESSION_MODIFICATION_REQUEST_TYPE 					86
#define PFCP_REMOVE_BAR_TYPE 												87
#define PFCP_BAR_ID_TYPE 													88
#define PFCP_CP_FUNCTION_FEATURES_TYPE 										89
#define PFCP_USAGE_INFORMATION_TYPE 										90
#define PFCP_APPLICATION_INSTANCE_ID_TYPE 									91
#define PFCP_FLOW_INFORMATION_TYPE 											92
#define PFCP_UE_IP_ADDRESS_TYPE 											93
#define PFCP_PACKET_RATE_TYPE 												94
#define PFCP_OUTER_HEADER_REMOVAL_TYPE 										95
#define PFCP_RECOVERY_TIME_STAMP_TYPE 										96
#define PFCP_DL_FLOW_LEVEL_MARKING_TYPE 									97
#define PFCP_HEADER_ENRICHMENT_TYPE 										98
#define PFCP_ERROR_INDICATION_REPORT_TYPE 									99
#define PFCP_MEASUREMENT_INFORMATION_TYPE 									100
#define PFCP_NODE_REPORT_TYPE_TYPE 											101
#define PFCP_USER_PLANE_PATH_FAILURE_REPORT_TYPE 							102
#define PFCP_REMOTE_GTP_U_PEER_TYPE 										103
#define PFCP_UR_SEQN_TYPE 													104
#define PFCP_UPDATE_DUPLICATING_PARAMETERS_TYPE 							105
#define PFCP_ACTIVATE_PREDEFINED_RULES_TYPE 								106
#define PFCP_DEACTIVATE_PREDEFINED_RULES_TYPE 								107
#define PFCP_FAR_ID_TYPE 													108
#define PFCP_QER_ID_TYPE 													109
#define PFCP_OCI_FLAGS_TYPE 												110
#define PFCP_PFCP_ASSOCIATION_RELEASE_REQUEST_TYPE 							111
#define PFCP_GRACEFUL_RELEASE_PERIOD_TYPE 									112
#define PFCP_PDN_TYPE_TYPE 													113
#define PFCP_FAILED_RULE_ID_TYPE 											114
#define PFCP_TIME_QUOTA_MECHANISM_TYPE 										115
#define PFCP_USER_PLANE_IP_RESOURCE_INFORMATION_TYPE 						116
#define PFCP_USER_PLANE_INACTIVITY_TIMER_TYPE 								117
#define PFCP_AGGREGATED_URRS_TYPE 											118
#define PFCP_MULTIPLIER_TYPE 												119
#define PFCP_AGGREGATED_URR_ID_TYPE 										120
#define PFCP_SUBSEQUENT_VOLUME_QUOTA_TYPE 									121
#define PFCP_SUBSEQUENT_TIME_QUOTA_TYPE 									122
#define PFCP_RQI_TYPE 														123
#define PFCP_QFI_TYPE 														124
#define PFCP_QUERY_URR_REFERENCE_TYPE 										125
#define PFCP_ADDITIONAL_USAGE_REPORTS_INFORMATION_TYPE 						126
#define PFCP_CREATE_TRAFFIC_ENDPOINT_TYPE 									127
#define PFCP_CREATED_TRAFFIC_ENDPOINT_TYPE 									128
#define PFCP_UPDATE_TRAFFIC_ENDPOINT_TYPE 									129
#define PFCP_REMOVE_TRAFFIC_ENDPOINT_TYPE 									130
#define PFCP_TRAFFIC_ENDPOINT_ID_TYPE 										131
#define PFCP_ETHERNET_PACKET_FILTER_TYPE 									132
#define PFCP_MAC_ADDRESS_TYPE 												133
#define PFCP_C_TAG_TYPE 													134
#define PFCP_S_TAG_TYPE 													135
#define PFCP_ETHERTYPE_TYPE 												136
#define PFCP_PROXYING_TYPE 													137
#define PFCP_ETHERNET_FILTER_ID_TYPE 										138
#define PFCP_ETHERNET_FILTER_PROPERTIES_TYPE 								139
#define PFCP_SUGGESTED_BUFFERING_PACKETS_COUNT_TYPE 						140
#define PFCP_USER_ID_TYPE 													141
#define PFCP_ETHERNET_PDU_SESSION_INFORMATION_TYPE 							142
#define PFCP_ETHERNET_TRAFFIC_INFORMATION_TYPE 								143
#define PFCP_MAC_ADDRESSES_DETECTED_TYPE 									144
#define PFCP_MAC_ADDRESSES_REMOVED_TYPE 									145
#define PFCP_ETHERNET_INACTIVITY_TIMER_TYPE 								146
#define PFCP_ADDITIONAL_MONITORING_TIME_TYPE 								147
#define PFCP_EVENT_QUOTA_TYPE 												148
#define PFCP_EVENT_THRESHOLD_TYPE 											149
#define PFCP_SUBSEQUENT_EVENT_QUOTA_TYPE 									150
#define PFCP_SUBSEQUENT_EVENT_THRESHOLD_TYPE 								151
#define PFCP_TRACE_INFORMATION_TYPE 										152
#define PFCP_FRAMED_ROUTE_TYPE 												153
#define PFCP_FRAMED_ROUTING_TYPE 											154
#define PFCP_FRAMED_IPV6_ROUTE_TYPE 										155
#define PFCP_EVENT_TIME_STAMP_TYPE 											156
#define PFCP_AVERAGING_WINDOW_TYPE 											157
#define PFCP_PAGING_POLICY_INDICATOR_TYPE 									158
#define PFCP_APN_DNN_TYPE 													159
#define PFCP__INTERFACE_TYPE_TYPE 											160
#define PFCP_PFCPSRREQ_FLAGS_TYPE 											161
#define PFCP_PFCPAUREQ_FLAGS_TYPE 											162
#define PFCP_ACTIVATION_TIME_TYPE 											163
#define PFCP_DEACTIVATION_TIME_TYPE 										164
#define PFCP_CREATE_MAR_TYPE 												165
#define PFCP_ACCESS_FORWARDING_ACTION_INFORMATION_1_TYPE 					166
#define PFCP_ACCESS_FORWARDING_ACTION_INFORMATION_2_TYPE 					167
#define PFCP_REMOVE_MAR_TYPE 												168
#define PFCP_UPDATE_MAR_TYPE 												169
#define PFCP_MAR_ID_TYPE 													170
#define PFCP_STEERING_FUNCTIONALITY_TYPE 									171
#define PFCP_STEERING_MODE_TYPE 											172
#define PFCP_WEIGHT_TYPE 													173
#define PFCP_PRIORITY_TYPE 													174
#define PFCP_UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_1_TYPE 			175
#define PFCP_UPDATE_ACCESS_FORWARDING_ACTION_INFORMATION_2_TYPE 			176
#define PFCP_UE_IP_ADDRESS_POOL_IDENTITY_TYPE 								177
#define PFCP_ALTERNATIVE_SMF_IP_ADDRESS_TYPE 								178
#define PFCP_PACKET_REPLICATION_AND_DETECTION_CARRY_ON_INFORMATION_TYPE 	179
#define PFCP_SMF_SET_ID_TYPE 												180
#define PFCP_QUOTA_VALIDITY_TIME_TYPE 										181


typedef tlv_uint8_t pfcp_tlv_cause_t;
typedef tlv_uint8_t pfcp_tlv_source_interface_t;
typedef tlv_octet_t pfcp_tlv_f_teid_t;
typedef tlv_octet_t pfcp_tlv_network_instance_t;
typedef tlv_octet_t pfcp_tlv_sdf_filter_t;
typedef tlv_octet_t pfcp_tlv_application_id_t;
typedef tlv_uint8_t pfcp_tlv_gate_status_t;
typedef tlv_octet_t pfcp_tlv_mbr_t;
typedef tlv_octet_t pfcp_tlv_gbr_t;
typedef tlv_uint32_t pfcp_tlv_qer_correlation_id_t;
typedef tlv_uint32_t pfcp_tlv_precedence_t;
typedef tlv_octet_t pfcp_tlv_transport_level_marking_t;
typedef tlv_octet_t pfcp_tlv_volume_threshold_t;
typedef tlv_octet_t pfcp_tlv_time_threshold_t;
typedef tlv_octet_t pfcp_tlv_monitoring_time_t;
typedef tlv_octet_t pfcp_tlv_subsequent_volume_threshold_t;
typedef tlv_octet_t pfcp_tlv_subsequent_time_threshold_t;
typedef tlv_octet_t pfcp_tlv_inactivity_detection_time_t;
typedef tlv_uint8_t pfcp_tlv_reporting_triggers_t;
typedef tlv_octet_t pfcp_tlv_redirect_information_t;
typedef tlv_uint8_t pfcp_tlv_report_type_t;
typedef tlv_uint16_t pfcp_tlv_offending_ie_t;
typedef tlv_octet_t pfcp_tlv_forwarding_policy_t;
typedef tlv_uint8_t pfcp_tlv_destination_interface_t;
typedef tlv_octet_t pfcp_tlv_up_function_features_t;
typedef tlv_uint8_t pfcp_tlv_apply_action_t;
typedef tlv_octet_t pfcp_tlv_downlink_data_service_information_t;
typedef tlv_octet_t pfcp_tlv_downlink_data_notification_delay_t;
typedef tlv_octet_t pfcp_tlv_dl_buffering_duration_t;
typedef tlv_octet_t pfcp_tlv_dl_buffering_suggested_packet_count_t;
typedef tlv_uint8_t pfcp_tlv_pfcpsmreq_flags_t;
typedef tlv_uint8_t pfcp_tlv_pfcpsrrsp_flags_t;
typedef tlv_octet_t pfcp_tlv_sequence_number_t;
typedef tlv_octet_t pfcp_tlv_metric_t;
typedef tlv_octet_t pfcp_tlv_timer_t;
typedef tlv_uint16_t pfcp_tlv_pdr_id_t;
typedef tlv_octet_t pfcp_tlv_f_seid_t;
typedef tlv_octet_t pfcp_tlv_node_id_t;
typedef tlv_octet_t pfcp_tlv_pfd_contents_t;
typedef tlv_uint8_t pfcp_tlv_measurement_method_t;
typedef tlv_octet_t pfcp_tlv_usage_report_trigger_t;
typedef tlv_octet_t pfcp_tlv_measurement_period_t;
typedef tlv_octet_t pfcp_tlv_fq_csid_t;
typedef tlv_octet_t pfcp_tlv_volume_measurement_t;
typedef tlv_octet_t pfcp_tlv_duration_measurement_t;
typedef tlv_octet_t pfcp_tlv_time_of_first_packet_t;
typedef tlv_octet_t pfcp_tlv_time_of_last_packet_t;
typedef tlv_octet_t pfcp_tlv_quota_holding_time_t;
typedef tlv_octet_t pfcp_tlv_dropped_dl_traffic_threshold_t;
typedef tlv_octet_t pfcp_tlv_volume_quota_t;
typedef tlv_octet_t pfcp_tlv_time_quota_t;
typedef tlv_octet_t pfcp_tlv_start_time_t;
typedef tlv_octet_t pfcp_tlv_end_time_t;
typedef tlv_uint32_t pfcp_tlv_urr_id_t;
typedef tlv_octet_t pfcp_tlv_linked_urr_id_t;
typedef tlv_octet_t pfcp_tlv_outer_header_creation_t;
typedef tlv_uint8_t pfcp_tlv_bar_id_t;
typedef tlv_uint8_t pfcp_tlv_cp_function_features_t;
typedef tlv_octet_t pfcp_tlv_usage_information_t;
typedef tlv_octet_t pfcp_tlv_application_instance_id_t;
typedef tlv_octet_t pfcp_tlv_flow_information_t;
typedef tlv_octet_t pfcp_tlv_ue_ip_address_t;
typedef tlv_octet_t pfcp_tlv_packet_rate_t;
typedef tlv_octet_t pfcp_tlv_outer_header_removal_t;
typedef tlv_uint32_t pfcp_tlv_recovery_time_stamp_t;
typedef tlv_octet_t pfcp_tlv_dl_flow_level_marking_t;
typedef tlv_octet_t pfcp_tlv_header_enrichment_t;
typedef tlv_octet_t pfcp_tlv_measurement_information_t;
typedef tlv_octet_t pfcp_tlv_node_report_type_t;
typedef tlv_octet_t pfcp_tlv_remote_gtp_u_peer_t;
typedef tlv_octet_t pfcp_tlv_ur_seqn_t;
typedef tlv_octet_t pfcp_tlv_activate_predefined_rules_t;
typedef tlv_octet_t pfcp_tlv_deactivate_predefined_rules_t;
typedef tlv_uint32_t pfcp_tlv_far_id_t;
typedef tlv_uint32_t pfcp_tlv_qer_id_t;
typedef tlv_octet_t pfcp_tlv_oci_flags_t;
typedef tlv_octet_t pfcp_tlv_pfcp_association_release_request_t;
typedef tlv_octet_t pfcp_tlv_graceful_release_period_t;
typedef tlv_uint8_t pfcp_tlv_pdn_type_t;
typedef tlv_octet_t pfcp_tlv_failed_rule_id_t;
typedef tlv_octet_t pfcp_tlv_time_quota_mechanism_t;
typedef tlv_octet_t pfcp_tlv_user_plane_ip_resource_information_t;
typedef tlv_octet_t pfcp_tlv_user_plane_inactivity_timer_t;
typedef tlv_octet_t pfcp_tlv_aggregated_urrs_t;
typedef tlv_octet_t pfcp_tlv_multiplier_t;
typedef tlv_octet_t pfcp_tlv_aggregated_urr_id_t;
typedef tlv_octet_t pfcp_tlv_subsequent_volume_quota_t;
typedef tlv_octet_t pfcp_tlv_subsequent_time_quota_t;
typedef tlv_uint8_t pfcp_tlv_rqi_t;
typedef tlv_uint8_t pfcp_tlv_qfi_t;
typedef tlv_octet_t pfcp_tlv_query_urr_reference_t;
typedef tlv_octet_t pfcp_tlv_additional_usage_reports_information_t;
typedef tlv_octet_t pfcp_tlv_update_traffic_endpoint_t;
typedef tlv_octet_t pfcp_tlv_traffic_endpoint_id_t;
typedef tlv_octet_t pfcp_tlv_mac_address_t;
typedef tlv_octet_t pfcp_tlv_c_tag_t;
typedef tlv_octet_t pfcp_tlv_s_tag_t;
typedef tlv_octet_t pfcp_tlv_ethertype_t;
typedef tlv_octet_t pfcp_tlv_proxying_t;
typedef tlv_octet_t pfcp_tlv_ethernet_filter_id_t;
typedef tlv_octet_t pfcp_tlv_ethernet_filter_properties_t;
typedef tlv_octet_t pfcp_tlv_suggested_buffering_packets_count_t;
typedef tlv_octet_t pfcp_tlv_user_id_t;
typedef tlv_octet_t pfcp_tlv_ethernet_pdu_session_information_t;
typedef tlv_octet_t pfcp_tlv_mac_addresses_detected_t;
typedef tlv_octet_t pfcp_tlv_mac_addresses_removed_t;
typedef tlv_octet_t pfcp_tlv_ethernet_inactivity_timer_t;
typedef tlv_octet_t pfcp_tlv_additional_monitoring_time_t;
typedef tlv_octet_t pfcp_tlv_event_quota_t;
typedef tlv_octet_t pfcp_tlv_event_threshold_t;
typedef tlv_octet_t pfcp_tlv_subsequent_event_quota_t;
typedef tlv_octet_t pfcp_tlv_subsequent_event_threshold_t;
typedef tlv_octet_t pfcp_tlv_trace_information_t;
typedef tlv_octet_t pfcp_tlv_framed_route_t;
typedef tlv_octet_t pfcp_tlv_framed_routing_t;
typedef tlv_octet_t pfcp_tlv_framed_ipv6_route_t;
typedef tlv_octet_t pfcp_tlv_event_time_stamp_t;
typedef tlv_uint32_t pfcp_tlv_averaging_window_t;
typedef tlv_uint8_t pfcp_tlv_paging_policy_indicator_t;
typedef tlv_octet_t pfcp_tlv_apn_dnn_t;
typedef tlv_octet_t pfcp_tlv__interface_type_t;
typedef tlv_uint8_t pfcp_tlv_pfcpsrreq_flags_t;
typedef tlv_uint8_t pfcp_tlv_pfcpaureq_flags_t;
typedef tlv_octet_t pfcp_tlv_activation_time_t;
typedef tlv_octet_t pfcp_tlv_deactivation_time_t;
typedef tlv_octet_t pfcp_tlv_mar_id_t;
typedef tlv_octet_t pfcp_tlv_steering_functionality_t;
typedef tlv_octet_t pfcp_tlv_steering_mode_t;
typedef tlv_octet_t pfcp_tlv_weight_t;
typedef tlv_octet_t pfcp_tlv_priority_t;
typedef tlv_octet_t pfcp_tlv_ue_ip_address_pool_identity_t;
typedef tlv_octet_t pfcp_tlv_alternative_smf_ip_address_t;
typedef tlv_octet_t pfcp_tlv_packet_replication_and_detection_carry_on_information_t;
typedef tlv_octet_t pfcp_tlv_smf_set_id_t;
typedef tlv_octet_t pfcp_tlv_quota_validity_time_t;


#pragma pack(4)
typedef struct pfcp_tlv_ethernet_packet_filter_s {
    tlv_presence_t presence;
    pfcp_tlv_ethernet_filter_id_t ethernet_filter_id;
    pfcp_tlv_ethernet_filter_properties_t ethernet_filter_properties;
    pfcp_tlv_mac_address_t mac_address;
    pfcp_tlv_ethertype_t ethertype;
    pfcp_tlv_c_tag_t c_tag;
    pfcp_tlv_s_tag_t s_tag;
    pfcp_tlv_sdf_filter_t sdf_filter[8];
} pfcp_tlv_ethernet_packet_filter_t;

#pragma pack(4)
typedef struct pfcp_tlv_pdi_s {
    tlv_presence_t presence;
    pfcp_tlv_source_interface_t source_interface;
    pfcp_tlv_f_teid_t local_f_teid;
    pfcp_tlv_network_instance_t network_instance;
    pfcp_tlv_ue_ip_address_t ue_ip_address;
    pfcp_tlv_traffic_endpoint_id_t traffic_endpoint_id;
    pfcp_tlv_sdf_filter_t sdf_filter[8];
    pfcp_tlv_application_id_t application_id;
    pfcp_tlv_ethernet_pdu_session_information_t ethernet_pdu_session_information;
    pfcp_tlv_ethernet_packet_filter_t ethernet_packet_filter;
    pfcp_tlv_qfi_t qfi;
    pfcp_tlv_framed_route_t framed_route;
    pfcp_tlv_framed_routing_t framed_routing;
    pfcp_tlv_framed_ipv6_route_t framed_ipv6_route;
    pfcp_tlv__interface_type_t source_interface_type;
} pfcp_tlv_pdi_t;

#pragma pack(4)
typedef struct pfcp_tlv_create_pdr_s {
    tlv_presence_t presence;
    pfcp_tlv_pdr_id_t pdr_id;
    pfcp_tlv_precedence_t precedence;
    pfcp_tlv_pdi_t pdi;
    pfcp_tlv_outer_header_removal_t outer_header_removal;
    pfcp_tlv_far_id_t far_id;
    pfcp_tlv_urr_id_t urr_id;
    pfcp_tlv_qer_id_t qer_id;
    pfcp_tlv_activate_predefined_rules_t activate_predefined_rules;
    pfcp_tlv_activation_time_t activation_time;
    pfcp_tlv_deactivation_time_t deactivation_time;
    pfcp_tlv_mar_id_t mar_id;
    pfcp_tlv_packet_replication_and_detection_carry_on_information_t packet_replication_and_detection_carry_on_information;
} pfcp_tlv_create_pdr_t;

#pragma pack(4)
typedef struct pfcp_tlv_forwarding_parameters_s {
    tlv_presence_t presence;
    pfcp_tlv_destination_interface_t destination_interface;
    pfcp_tlv_network_instance_t network_instance;
    pfcp_tlv_redirect_information_t redirect_information;
    pfcp_tlv_outer_header_creation_t outer_header_creation;
    pfcp_tlv_transport_level_marking_t transport_level_marking;
    pfcp_tlv_forwarding_policy_t forwarding_policy;
    pfcp_tlv_header_enrichment_t header_enrichment;
    pfcp_tlv_traffic_endpoint_id_t linked_traffic_endpoint_id;
    pfcp_tlv_proxying_t proxying;
    pfcp_tlv__interface_type_t destination_interface_type;
} pfcp_tlv_forwarding_parameters_t;

#pragma pack(4)
typedef struct pfcp_tlv_duplicating_parameters_s {
    tlv_presence_t presence;
    pfcp_tlv_destination_interface_t destination_interface;
    pfcp_tlv_outer_header_creation_t outer_header_creation;
    pfcp_tlv_transport_level_marking_t transport_level_marking;
    pfcp_tlv_forwarding_policy_t forwarding_policy;
} pfcp_tlv_duplicating_parameters_t;

#pragma pack(4)
typedef struct pfcp_tlv_create_far_s {
    tlv_presence_t presence;
    pfcp_tlv_far_id_t far_id;
    pfcp_tlv_apply_action_t apply_action;
    pfcp_tlv_forwarding_parameters_t forwarding_parameters;
    pfcp_tlv_duplicating_parameters_t duplicating_parameters;
    pfcp_tlv_bar_id_t bar_id;
} pfcp_tlv_create_far_t;

#pragma pack(4)
typedef struct pfcp_tlv_update_forwarding_parameters_s {
    tlv_presence_t presence;
    pfcp_tlv_destination_interface_t destination_interface;
    pfcp_tlv_network_instance_t network_instance;
    pfcp_tlv_redirect_information_t redirect_information;
    pfcp_tlv_outer_header_creation_t outer_header_creation;
    pfcp_tlv_transport_level_marking_t transport_level_marking;
    pfcp_tlv_forwarding_policy_t forwarding_policy;
    pfcp_tlv_header_enrichment_t header_enrichment;
    pfcp_tlv_pfcpsmreq_flags_t pfcpsmreq_flags;
    pfcp_tlv_traffic_endpoint_id_t linked_traffic_endpoint_id;
    pfcp_tlv__interface_type_t destination_interface_type;
} pfcp_tlv_update_forwarding_parameters_t;

#pragma pack(4)
typedef struct pfcp_tlv_update_duplicating_parameters_s {
    tlv_presence_t presence;
    pfcp_tlv_destination_interface_t destination_interface;
    pfcp_tlv_outer_header_creation_t outer_header_creation;
    pfcp_tlv_transport_level_marking_t transport_level_marking;
    pfcp_tlv_forwarding_policy_t forwarding_policy;
} pfcp_tlv_update_duplicating_parameters_t;

#pragma pack(4)
typedef struct pfcp_tlv_update_far_s {
    tlv_presence_t presence;
    pfcp_tlv_far_id_t far_id;
    pfcp_tlv_apply_action_t apply_action;
    pfcp_tlv_update_forwarding_parameters_t update_forwarding_parameters;
    pfcp_tlv_update_duplicating_parameters_t update_duplicating_parameters;
    pfcp_tlv_bar_id_t bar_id;
} pfcp_tlv_update_far_t;

#pragma pack(4)
typedef struct pfcp_tlv_pfd_context_s {
    tlv_presence_t presence;
    pfcp_tlv_pfd_contents_t pfd_contents;
} pfcp_tlv_pfd_context_t;

#pragma pack(4)
typedef struct pfcp_tlv_application_id_s_pfds_s {
    tlv_presence_t presence;
    pfcp_tlv_application_id_t application_id;
    pfcp_tlv_pfd_context_t pfd_context;
} pfcp_tlv_application_id_s_pfds_t;

#pragma pack(4)
typedef struct pfcp_tlv_ethernet_traffic_information_s {
    tlv_presence_t presence;
    pfcp_tlv_mac_addresses_detected_t mac_addresses_detected;
    pfcp_tlv_mac_addresses_removed_t mac_addresses_removed;
} pfcp_tlv_ethernet_traffic_information_t;

#pragma pack(4)
typedef struct pfcp_tlv_access_forwarding_action_information_1_s {
    tlv_presence_t presence;
    pfcp_tlv_far_id_t far_id;
    pfcp_tlv_weight_t weight;
    pfcp_tlv_priority_t priority;
    pfcp_tlv_urr_id_t urr_id;
} pfcp_tlv_access_forwarding_action_information_1_t;

#pragma pack(4)
typedef struct pfcp_tlv_access_forwarding_action_information_2_s {
    tlv_presence_t presence;
    pfcp_tlv_far_id_t far_id;
    pfcp_tlv_weight_t weight;
    pfcp_tlv_priority_t priority;
    pfcp_tlv_urr_id_t urr_id;
} pfcp_tlv_access_forwarding_action_information_2_t;

#pragma pack(4)
typedef struct pfcp_tlv_update_access_forwarding_action_information_1_s {
    tlv_presence_t presence;
    pfcp_tlv_far_id_t far_id;
    pfcp_tlv_weight_t weight;
    pfcp_tlv_priority_t priority;
    pfcp_tlv_urr_id_t urr_id;
} pfcp_tlv_update_access_forwarding_action_information_1_t;

#pragma pack(4)
typedef struct pfcp_tlv_update_access_forwarding_action_information_2_s {
    tlv_presence_t presence;
    pfcp_tlv_far_id_t far_id;
    pfcp_tlv_weight_t weight;
    pfcp_tlv_priority_t priority;
    pfcp_tlv_urr_id_t urr_id;
} pfcp_tlv_update_access_forwarding_action_information_2_t;

#pragma pack(4)
typedef struct pfcp_tlv_create_urr_s {
    tlv_presence_t presence;
    pfcp_tlv_urr_id_t urr_id;
    pfcp_tlv_measurement_method_t measurement_method;
    pfcp_tlv_reporting_triggers_t reporting_triggers;
    pfcp_tlv_measurement_period_t measurement_period;
    pfcp_tlv_volume_threshold_t volume_threshold;
    pfcp_tlv_volume_quota_t volume_quota;
    pfcp_tlv_event_threshold_t event_threshold;
    pfcp_tlv_event_quota_t event_quota;
    pfcp_tlv_time_threshold_t time_threshold;
    pfcp_tlv_time_quota_t time_quota;
    pfcp_tlv_quota_holding_time_t quota_holding_time;
    pfcp_tlv_dropped_dl_traffic_threshold_t dropped_dl_traffic_threshold;
    pfcp_tlv_quota_validity_time_t quota_validity_time;
    pfcp_tlv_monitoring_time_t monitoring_time;
    pfcp_tlv_subsequent_volume_threshold_t subsequent_volume_threshold;
    pfcp_tlv_subsequent_time_threshold_t subsequent_time_threshold;
    pfcp_tlv_subsequent_volume_quota_t subsequent_volume_quota;
    pfcp_tlv_subsequent_time_quota_t subsequent_time_quota;
    pfcp_tlv_subsequent_event_threshold_t subsequent_event_threshold;
    pfcp_tlv_subsequent_event_quota_t subsequent_event_quota;
    pfcp_tlv_inactivity_detection_time_t inactivity_detection_time;
    pfcp_tlv_linked_urr_id_t linked_urr_id;
    pfcp_tlv_measurement_information_t measurement_information;
    pfcp_tlv_time_quota_mechanism_t time_quota_mechanism;
    pfcp_tlv_aggregated_urrs_t aggregated_urrs;
    pfcp_tlv_far_id_t far_id_for_quota_action;
    pfcp_tlv_ethernet_inactivity_timer_t ethernet_inactivity_timer;
    pfcp_tlv_additional_monitoring_time_t additional_monitoring_time;
} pfcp_tlv_create_urr_t;

#pragma pack(4)
typedef struct pfcp_tlv_create_qer_s {
    tlv_presence_t presence;
    pfcp_tlv_qer_id_t qer_id;
    pfcp_tlv_qer_correlation_id_t qer_correlation_id;
    pfcp_tlv_gate_status_t gate_status;
    pfcp_tlv_mbr_t maximum_bitrate;
    pfcp_tlv_gbr_t guaranteed_bitrate;
    pfcp_tlv_packet_rate_t packet_rate;
    pfcp_tlv_dl_flow_level_marking_t dl_flow_level_marking;
    pfcp_tlv_qfi_t qos_flow_identifier;
    pfcp_tlv_rqi_t reflective_qos;
    pfcp_tlv_paging_policy_indicator_t paging_policy_indicator;
    pfcp_tlv_averaging_window_t averaging_window;
} pfcp_tlv_create_qer_t;

#pragma pack(4)
typedef struct pfcp_tlv_created_pdr_s {
    tlv_presence_t presence;
    pfcp_tlv_pdr_id_t pdr_id;
    pfcp_tlv_f_teid_t local_f_teid;
    pfcp_tlv_ue_ip_address_t ue_ip_address;
} pfcp_tlv_created_pdr_t;

#pragma pack(4)
typedef struct pfcp_tlv_update_pdr_s {
    tlv_presence_t presence;
    pfcp_tlv_pdr_id_t pdr_id;
    pfcp_tlv_outer_header_removal_t outer_header_removal;
    pfcp_tlv_precedence_t precedence;
    pfcp_tlv_pdi_t pdi;
    pfcp_tlv_far_id_t far_id;
    pfcp_tlv_urr_id_t urr_id;
    pfcp_tlv_qer_id_t qer_id;
    pfcp_tlv_activate_predefined_rules_t activate_predefined_rules;
    pfcp_tlv_deactivate_predefined_rules_t deactivate_predefined_rules;
    pfcp_tlv_activation_time_t activation_time;
    pfcp_tlv_deactivation_time_t deactivation_time;
} pfcp_tlv_update_pdr_t;

#pragma pack(4)
typedef struct pfcp_tlv_update_bar_pfcp_session_report_response_s {
    tlv_presence_t presence;
    pfcp_tlv_bar_id_t bar_id;
    pfcp_tlv_downlink_data_notification_delay_t downlink_data_notification_delay;
    pfcp_tlv_dl_buffering_duration_t dl_buffering_duration;
    pfcp_tlv_dl_buffering_suggested_packet_count_t dl_buffering_suggested_packet_count;
    pfcp_tlv_suggested_buffering_packets_count_t suggested_buffering_packets_count;
} pfcp_tlv_update_bar_pfcp_session_report_response_t;

#pragma pack(4)
typedef struct pfcp_tlv_update_urr_s {
    tlv_presence_t presence;
    pfcp_tlv_urr_id_t urr_id;
    pfcp_tlv_measurement_method_t measurement_method;
    pfcp_tlv_reporting_triggers_t reporting_triggers;
    pfcp_tlv_measurement_period_t measurement_period;
    pfcp_tlv_volume_threshold_t volume_threshold;
    pfcp_tlv_volume_quota_t volume_quota;
    pfcp_tlv_time_threshold_t time_threshold;
    pfcp_tlv_time_quota_t time_quota;
    pfcp_tlv_event_threshold_t event_threshold;
    pfcp_tlv_event_quota_t event_quota;
    pfcp_tlv_quota_holding_time_t quota_holding_time;
    pfcp_tlv_dropped_dl_traffic_threshold_t dropped_dl_traffic_threshold;
    pfcp_tlv_quota_validity_time_t quota_validity_time;
    pfcp_tlv_monitoring_time_t monitoring_time;
    pfcp_tlv_subsequent_volume_threshold_t subsequent_volume_threshold;
    pfcp_tlv_subsequent_time_threshold_t subsequent_time_threshold;
    pfcp_tlv_subsequent_volume_quota_t subsequent_volume_quota;
    pfcp_tlv_subsequent_time_quota_t subsequent_time_quota;
    pfcp_tlv_subsequent_event_threshold_t subsequent_event_threshold;
    pfcp_tlv_subsequent_event_quota_t subsequent_event_quota;
    pfcp_tlv_inactivity_detection_time_t inactivity_detection_time;
    pfcp_tlv_linked_urr_id_t linked_urr_id;
    pfcp_tlv_measurement_information_t measurement_information;
    pfcp_tlv_time_quota_mechanism_t time_quota_mechanism;
    pfcp_tlv_aggregated_urrs_t aggregated_urrs;
    pfcp_tlv_far_id_t far_id_for_quota_action;
    pfcp_tlv_ethernet_inactivity_timer_t ethernet_inactivity_timer;
    pfcp_tlv_additional_monitoring_time_t additional_monitoring_time;
} pfcp_tlv_update_urr_t;

#pragma pack(4)
typedef struct pfcp_tlv_update_qer_s {
    tlv_presence_t presence;
    pfcp_tlv_qer_id_t qer_id;
    pfcp_tlv_qer_correlation_id_t qer_correlation_id;
    pfcp_tlv_gate_status_t gate_status;
    pfcp_tlv_mbr_t maximum_bitrate;
    pfcp_tlv_gbr_t guaranteed_bitrate;
    pfcp_tlv_packet_rate_t packet_rate;
    pfcp_tlv_dl_flow_level_marking_t dl_flow_level_marking;
    pfcp_tlv_qfi_t qos_flow_identifier;
    pfcp_tlv_rqi_t reflective_qos;
    pfcp_tlv_paging_policy_indicator_t paging_policy_indicator;
    pfcp_tlv_averaging_window_t averaging_window;
} pfcp_tlv_update_qer_t;

#pragma pack(4)
typedef struct pfcp_tlv_remove_pdr_s {
    tlv_presence_t presence;
    pfcp_tlv_pdr_id_t pdr_id;
} pfcp_tlv_remove_pdr_t;

#pragma pack(4)
typedef struct pfcp_tlv_remove_far_s {
    tlv_presence_t presence;
    pfcp_tlv_far_id_t far_id;
} pfcp_tlv_remove_far_t;

#pragma pack(4)
typedef struct pfcp_tlv_remove_urr_s {
    tlv_presence_t presence;
    pfcp_tlv_urr_id_t urr_id;
} pfcp_tlv_remove_urr_t;

#pragma pack(4)
typedef struct pfcp_tlv_remove_qer_s {
    tlv_presence_t presence;
    pfcp_tlv_qer_id_t qer_id;
} pfcp_tlv_remove_qer_t;

#pragma pack(4)
typedef struct pfcp_tlv_load_control_information_s {
    tlv_presence_t presence;
    pfcp_tlv_sequence_number_t load_control_sequence_number;
    pfcp_tlv_metric_t load_metric;
} pfcp_tlv_load_control_information_t;

#pragma pack(4)
typedef struct pfcp_tlv_overload_control_information_s {
    tlv_presence_t presence;
    pfcp_tlv_sequence_number_t overload_control_sequence_number;
    pfcp_tlv_metric_t overload_reduction_metric;
    pfcp_tlv_timer_t period_of_validity;
    pfcp_tlv_oci_flags_t overload_control_information_flags;
} pfcp_tlv_overload_control_information_t;

#pragma pack(4)
typedef struct pfcp_tlv_application_detection_information_s {
    tlv_presence_t presence;
    pfcp_tlv_application_id_t application_id;
    pfcp_tlv_application_instance_id_t application_instance_id;
    pfcp_tlv_flow_information_t flow_information;
} pfcp_tlv_application_detection_information_t;

#pragma pack(4)
typedef struct pfcp_tlv_query_urr_s {
    tlv_presence_t presence;
    pfcp_tlv_urr_id_t urr_id;
} pfcp_tlv_query_urr_t;

#pragma pack(4)
typedef struct pfcp_tlv_usage_report_session_modification_response_s {
    tlv_presence_t presence;
    pfcp_tlv_urr_id_t urr_id;
    pfcp_tlv_ur_seqn_t ur_seqn;
    pfcp_tlv_usage_report_trigger_t usage_report_trigger;
    pfcp_tlv_start_time_t start_time;
    pfcp_tlv_end_time_t end_time;
    pfcp_tlv_volume_measurement_t volume_measurement;
    pfcp_tlv_duration_measurement_t duration_measurement;
    pfcp_tlv_time_of_first_packet_t time_of_first_packet;
    pfcp_tlv_time_of_last_packet_t time_of_last_packet;
    pfcp_tlv_usage_information_t usage_information;
    pfcp_tlv_query_urr_reference_t query_urr_reference;
    pfcp_tlv_ethernet_traffic_information_t ethernet_traffic_information;
} pfcp_tlv_usage_report_session_modification_response_t;

#pragma pack(4)
typedef struct pfcp_tlv_usage_report_session_deletion_response_s {
    tlv_presence_t presence;
    pfcp_tlv_urr_id_t urr_id;
    pfcp_tlv_ur_seqn_t ur_seqn;
    pfcp_tlv_usage_report_trigger_t usage_report_trigger;
    pfcp_tlv_start_time_t start_time;
    pfcp_tlv_end_time_t end_time;
    pfcp_tlv_volume_measurement_t volume_measurement;
    pfcp_tlv_duration_measurement_t duration_measurement;
    pfcp_tlv_time_of_first_packet_t time_of_first_packet;
    pfcp_tlv_time_of_last_packet_t time_of_last_packet;
    pfcp_tlv_usage_information_t usage_information;
    pfcp_tlv_ethernet_traffic_information_t ethernet_traffic_information;
} pfcp_tlv_usage_report_session_deletion_response_t;

#pragma pack(4)
typedef struct pfcp_tlv_usage_report_session_report_request_s {
    tlv_presence_t presence;
    pfcp_tlv_urr_id_t urr_id;
    pfcp_tlv_ur_seqn_t ur_seqn;
    pfcp_tlv_usage_report_trigger_t usage_report_trigger;
    pfcp_tlv_start_time_t start_time;
    pfcp_tlv_end_time_t end_time;
    pfcp_tlv_volume_measurement_t volume_measurement;
    pfcp_tlv_duration_measurement_t duration_measurement;
    pfcp_tlv_application_detection_information_t application_detection_information;
    pfcp_tlv_ue_ip_address_t ue_ip_address;
    pfcp_tlv_network_instance_t network_instance;
    pfcp_tlv_time_of_first_packet_t time_of_first_packet;
    pfcp_tlv_time_of_last_packet_t time_of_last_packet;
    pfcp_tlv_usage_information_t usage_information;
    pfcp_tlv_query_urr_reference_t query_urr_reference;
    pfcp_tlv_event_time_stamp_t event_time_stamp;
    pfcp_tlv_ethernet_traffic_information_t ethernet_traffic_information;
} pfcp_tlv_usage_report_session_report_request_t;

#pragma pack(4)
typedef struct pfcp_tlv_downlink_data_report_s {
    tlv_presence_t presence;
    pfcp_tlv_pdr_id_t pdr_id;
    pfcp_tlv_downlink_data_service_information_t downlink_data_service_information;
} pfcp_tlv_downlink_data_report_t;

#pragma pack(4)
typedef struct pfcp_tlv_create_bar_s {
    tlv_presence_t presence;
    pfcp_tlv_bar_id_t bar_id;
    pfcp_tlv_downlink_data_notification_delay_t downlink_data_notification_delay;
    pfcp_tlv_suggested_buffering_packets_count_t suggested_buffering_packets_count;
} pfcp_tlv_create_bar_t;

#pragma pack(4)
typedef struct pfcp_tlv_update_bar_session_modification_request_s {
    tlv_presence_t presence;
    pfcp_tlv_bar_id_t bar_id;
    pfcp_tlv_downlink_data_notification_delay_t downlink_data_notification_delay;
    pfcp_tlv_suggested_buffering_packets_count_t suggested_buffering_packets_count;
} pfcp_tlv_update_bar_session_modification_request_t;

#pragma pack(4)
typedef struct pfcp_tlv_remove_bar_s {
    tlv_presence_t presence;
    pfcp_tlv_bar_id_t bar_id;
} pfcp_tlv_remove_bar_t;

#pragma pack(4)
typedef struct pfcp_tlv_error_indication_report_s {
    tlv_presence_t presence;
    pfcp_tlv_f_teid_t remote_f_teid;
} pfcp_tlv_error_indication_report_t;

#pragma pack(4)
typedef struct pfcp_tlv_user_plane_path_failure_report_s {
    tlv_presence_t presence;
    pfcp_tlv_remote_gtp_u_peer_t remote_gtp_u_peer_;
} pfcp_tlv_user_plane_path_failure_report_t;

#pragma pack(4)
typedef struct pfcp_tlv_create_traffic_endpoint_s {
    tlv_presence_t presence;
    pfcp_tlv_traffic_endpoint_id_t traffic_endpoint_id;
    pfcp_tlv_f_teid_t local_f_teid;
    pfcp_tlv_network_instance_t network_instance;
    pfcp_tlv_ue_ip_address_t ue_ip_address;
    pfcp_tlv_ethernet_pdu_session_information_t ethernet_pdu_session_information;
    pfcp_tlv_framed_route_t framed_route;
    pfcp_tlv_framed_routing_t framed_routing;
    pfcp_tlv_framed_ipv6_route_t framed_ipv6_route;
    pfcp_tlv_qfi_t qfi;
} pfcp_tlv_create_traffic_endpoint_t;

#pragma pack(4)
typedef struct pfcp_tlv_created_traffic_endpoint_s {
    tlv_presence_t presence;
    pfcp_tlv_traffic_endpoint_id_t traffic_endpoint_id;
    pfcp_tlv_f_teid_t local_f_teid;
    pfcp_tlv_ue_ip_address_t ue_ip_address;
} pfcp_tlv_created_traffic_endpoint_t;


#pragma pack(4)
typedef struct pfcp_tlv_remove_traffic_endpoint_s {
    tlv_presence_t presence;
    pfcp_tlv_traffic_endpoint_id_t traffic_endpoint_id;
} pfcp_tlv_remove_traffic_endpoint_t;


#pragma pack(4)
typedef struct pfcp_tlv_create_mar_s {
    tlv_presence_t presence;
    pfcp_tlv_mar_id_t mar_id;
    pfcp_tlv_steering_functionality_t steering_functionality;
    pfcp_tlv_steering_mode_t steering_mode;
    pfcp_tlv_access_forwarding_action_information_1_t access_forwarding_action_information_1;
    pfcp_tlv_access_forwarding_action_information_2_t access_forwarding_action_information_2;
} pfcp_tlv_create_mar_t;

#pragma pack(4)
typedef struct pfcp_tlv_remove_mar_s {
    tlv_presence_t presence;
    pfcp_tlv_mar_id_t mar_id;
} pfcp_tlv_remove_mar_t;

#pragma pack(4)
typedef struct pfcp_tlv_update_mar_s {
    tlv_presence_t presence;
    pfcp_tlv_mar_id_t mar_id;
    pfcp_tlv_steering_functionality_t steering_functionality;
    pfcp_tlv_steering_mode_t steering_mode;
    pfcp_tlv_update_access_forwarding_action_information_1_t update_access_forwarding_action_information_1;
    pfcp_tlv_update_access_forwarding_action_information_2_t update_access_forwarding_action_information_2;
    pfcp_tlv_access_forwarding_action_information_1_t access_forwarding_action_information_1;
    pfcp_tlv_access_forwarding_action_information_2_t access_forwarding_action_information_2;
} pfcp_tlv_update_mar_t;

#pragma pack(4)
typedef struct pfcp_heartbeat_request_s {
    pfcp_tlv_recovery_time_stamp_t recovery_time_stamp;
} pfcp_heartbeat_request_t;


#pragma pack(4)
typedef struct pfcp_heartbeat_response_s {
    pfcp_tlv_recovery_time_stamp_t recovery_time_stamp;
} pfcp_heartbeat_response_t;

#pragma pack(4)
typedef struct pfcp_pfd_management_request_s {
    pfcp_tlv_application_id_s_pfds_t application_id_s_pfds;
} pfcp_pfd_management_request_t;

#pragma pack(4)
typedef struct pfcp_pfd_management_response_s {
    pfcp_tlv_cause_t cause;
    pfcp_tlv_offending_ie_t offending_ie;
} pfcp_pfd_management_response_t;

#pragma pack(4)
typedef struct pfcp_association_setup_request_s {
    pfcp_tlv_node_id_t node_id;
    pfcp_tlv_recovery_time_stamp_t recovery_time_stamp;
    pfcp_tlv_up_function_features_t up_function_features;
    pfcp_tlv_cp_function_features_t cp_function_features;
    pfcp_tlv_user_plane_ip_resource_information_t user_plane_ip_resource_information[4];
    pfcp_tlv_ue_ip_address_t ue_ip_address_pool_identity;
    pfcp_tlv_alternative_smf_ip_address_t alternative_smf_ip_address;
    pfcp_tlv_smf_set_id_t smf_set_id;
} pfcp_association_setup_request_t;


#pragma pack(4)
typedef struct pfcp_association_setup_response_s {
    pfcp_tlv_node_id_t node_id;
    pfcp_tlv_cause_t cause;
    pfcp_tlv_recovery_time_stamp_t recovery_time_stamp;
    pfcp_tlv_up_function_features_t up_function_features;
    pfcp_tlv_cp_function_features_t cp_function_features;
    pfcp_tlv_user_plane_ip_resource_information_t user_plane_ip_resource_information[4];
    pfcp_tlv_alternative_smf_ip_address_t alternative_smf_ip_address;
} pfcp_association_setup_response_t;


#pragma pack(4)
typedef struct pfcp_association_update_request_s {
    pfcp_tlv_node_id_t node_id;
    pfcp_tlv_up_function_features_t up_function_features;
    pfcp_tlv_cp_function_features_t cp_function_features;
    pfcp_tlv_pfcp_association_release_request_t pfcp_association_release_request;
    pfcp_tlv_graceful_release_period_t graceful_release_period;
    pfcp_tlv_user_plane_ip_resource_information_t user_plane_ip_resource_information[4];
    pfcp_tlv_pfcpaureq_flags_t pfcpaureq_flags;
    pfcp_tlv_alternative_smf_ip_address_t alternative_smf_ip_address;
} pfcp_association_update_request_t;


#pragma pack(4)
typedef struct pfcp_association_update_response_s {
    pfcp_tlv_node_id_t node_id;
    pfcp_tlv_cause_t cause;
    pfcp_tlv_up_function_features_t up_function_features;
    pfcp_tlv_cp_function_features_t cp_function_features;
} pfcp_association_update_response_t;


#pragma pack(4)
typedef struct pfcp_association_release_request_s {
    pfcp_tlv_node_id_t node_id;
} pfcp_association_release_request_t;


#pragma pack(4)
typedef struct pfcp_association_release_response_s {
    pfcp_tlv_node_id_t node_id;
    pfcp_tlv_cause_t cause;
} pfcp_association_release_response_t;


#pragma pack(4)
typedef struct pfcp_version_not_supported_response_s {
} pfcp_version_not_supported_response_t;


#pragma pack(4)
typedef struct pfcp_node_report_request_s {
    pfcp_tlv_node_id_t node_id;
    pfcp_tlv_node_report_type_t node_report_type;
    pfcp_tlv_user_plane_path_failure_report_t user_plane_path_failure_report;
} pfcp_node_report_request_t;


#pragma pack(4)
typedef struct pfcp_node_report_response_s {
    pfcp_tlv_node_id_t node_id;
    pfcp_tlv_cause_t cause;
    pfcp_tlv_offending_ie_t offending_ie;
} pfcp_node_report_response_t;

#pragma pack(4)
typedef struct pfcp_session_set_deletion_request_s {
    pfcp_tlv_node_id_t node_id;
    pfcp_tlv_fq_csid_t sgw_c_fq_csid;
    pfcp_tlv_fq_csid_t pgw_c_fq_csid;
    pfcp_tlv_fq_csid_t sgw_u_fq_csid;
    pfcp_tlv_fq_csid_t pgw_u_fq_csid;
    pfcp_tlv_fq_csid_t twan_fq_csid;
    pfcp_tlv_fq_csid_t epdg_fq_csid;
    pfcp_tlv_fq_csid_t mme_fq_csid;
} pfcp_session_set_deletion_request_t;


#pragma pack(4)
typedef struct pfcp_session_set_deletion_response_s {
    pfcp_tlv_node_id_t node_id;
    pfcp_tlv_cause_t cause;
    pfcp_tlv_offending_ie_t offending_ie;
} pfcp_session_set_deletion_response_t;


#pragma pack(4)
typedef struct pfcp_session_establishment_request_s {
    pfcp_tlv_node_id_t node_id;
    pfcp_tlv_f_seid_t cp_f_seid;
    pfcp_tlv_create_pdr_t create_pdr[8];
    pfcp_tlv_create_far_t create_far[8];
    pfcp_tlv_create_urr_t create_urr[2];
    pfcp_tlv_create_qer_t create_qer[4];
    pfcp_tlv_create_bar_t create_bar;
    pfcp_tlv_create_traffic_endpoint_t create_traffic_endpoint;
    pfcp_tlv_pdn_type_t pdn_type;
    pfcp_tlv_fq_csid_t sgw_c_fq_csid;
    pfcp_tlv_fq_csid_t mme_fq_csid;
    pfcp_tlv_fq_csid_t pgw_c_fq_csid;
    pfcp_tlv_fq_csid_t epdg_fq_csid;
    pfcp_tlv_fq_csid_t twan_fq_csid;
    pfcp_tlv_user_plane_inactivity_timer_t user_plane_inactivity_timer;
    pfcp_tlv_user_id_t user_id;
    pfcp_tlv_trace_information_t trace_information;
    pfcp_tlv_apn_dnn_t apn_dnn;
    pfcp_tlv_create_mar_t create_mar;
} pfcp_session_establishment_request_t;


#pragma pack(4)
typedef struct pfcp_session_establishment_response_s {
    pfcp_tlv_node_id_t node_id;
    pfcp_tlv_cause_t cause;
    pfcp_tlv_offending_ie_t offending_ie;
    pfcp_tlv_f_seid_t up_f_seid;
    pfcp_tlv_created_pdr_t created_pdr[8];
    pfcp_tlv_load_control_information_t load_control_information;
    pfcp_tlv_overload_control_information_t overload_control_information;
    pfcp_tlv_fq_csid_t sgw_u_fq_csid;
    pfcp_tlv_fq_csid_t pgw_u_fq_csid;
    pfcp_tlv_failed_rule_id_t failed_rule_id;
    pfcp_tlv_created_traffic_endpoint_t created_traffic_endpoint;
} pfcp_session_establishment_response_t;


#pragma pack(4)
typedef struct pfcp_session_modification_request_s {
    pfcp_tlv_f_seid_t cp_f_seid;
    pfcp_tlv_remove_pdr_t remove_pdr[8];
    pfcp_tlv_remove_far_t remove_far[8];
    pfcp_tlv_remove_urr_t remove_urr[2];
    pfcp_tlv_remove_qer_t remove_qer[4];
    pfcp_tlv_remove_bar_t remove_bar;
    pfcp_tlv_remove_traffic_endpoint_t remove_traffic_endpoint;
    pfcp_tlv_create_pdr_t create_pdr[8];
    pfcp_tlv_create_far_t create_far[8];
    pfcp_tlv_create_urr_t create_urr[2];
    pfcp_tlv_create_qer_t create_qer[4];
    pfcp_tlv_create_bar_t create_bar;
    pfcp_tlv_create_traffic_endpoint_t create_traffic_endpoint;
    pfcp_tlv_update_pdr_t update_pdr[8];
    pfcp_tlv_update_far_t update_far[8];
    pfcp_tlv_update_urr_t update_urr[2];
    pfcp_tlv_update_qer_t update_qer[4];
    pfcp_tlv_update_bar_session_modification_request_t update_bar;
    pfcp_tlv_update_traffic_endpoint_t update_traffic_endpoint;
    pfcp_tlv_pfcpsmreq_flags_t pfcpsmreq_flags;
    pfcp_tlv_query_urr_t query_urr;
    pfcp_tlv_fq_csid_t pgw_c_fq_csid;
    pfcp_tlv_fq_csid_t sgw_c_fq_csid;
    pfcp_tlv_fq_csid_t mme_fq_csid;
    pfcp_tlv_fq_csid_t epdg_fq_csid;
    pfcp_tlv_fq_csid_t twan_fq_csid;
    pfcp_tlv_user_plane_inactivity_timer_t user_plane_inactivity_timer;
    pfcp_tlv_query_urr_reference_t query_urr_reference;
    pfcp_tlv_trace_information_t trace_information;
    pfcp_tlv_remove_mar_t remove_mar;
    pfcp_tlv_update_mar_t update_mar;
    pfcp_tlv_create_mar_t create_mar;
    pfcp_tlv_node_id_t node_id;
} pfcp_session_modification_request_t;


#pragma pack(4)
typedef struct pfcp_session_modification_response_s {
    pfcp_tlv_cause_t cause;
    pfcp_tlv_offending_ie_t offending_ie;
    pfcp_tlv_created_pdr_t created_pdr[8];
    pfcp_tlv_load_control_information_t load_control_information;
    pfcp_tlv_overload_control_information_t overload_control_information;
    pfcp_tlv_usage_report_session_modification_response_t usage_report;
    pfcp_tlv_failed_rule_id_t failed_rule_id;
    pfcp_tlv_additional_usage_reports_information_t additional_usage_reports_information;
    pfcp_tlv_created_traffic_endpoint_t created_updated_traffic_endpoint;
} pfcp_session_modification_response_t;


#pragma pack(4)
typedef struct pfcp_session_deletion_request_s {
} pfcp_session_deletion_request_t;


#pragma pack(4)
typedef struct pfcp_session_deletion_response_s {
    pfcp_tlv_cause_t cause;
    pfcp_tlv_offending_ie_t offending_ie;
    pfcp_tlv_load_control_information_t load_control_information;
    pfcp_tlv_overload_control_information_t overload_control_information;
    pfcp_tlv_usage_report_session_deletion_response_t usage_report;
} pfcp_session_deletion_response_t;


#pragma pack(4)
typedef struct pfcp_session_report_request_s {
    pfcp_tlv_report_type_t report_type;
    pfcp_tlv_downlink_data_report_t downlink_data_report;
    pfcp_tlv_usage_report_session_report_request_t usage_report;
    pfcp_tlv_error_indication_report_t error_indication_report;
    pfcp_tlv_load_control_information_t load_control_information;
    pfcp_tlv_overload_control_information_t overload_control_information;
    pfcp_tlv_additional_usage_reports_information_t additional_usage_reports_information;
    pfcp_tlv_pfcpsrreq_flags_t pfcpsrreq_flags;
    pfcp_tlv_f_seid_t old_cp_f_seid;
} pfcp_session_report_request_t;


#pragma pack(4)
typedef struct pfcp_session_report_response_s {
    pfcp_tlv_cause_t cause;
    pfcp_tlv_offending_ie_t offending_ie;
    pfcp_tlv_update_bar_pfcp_session_report_response_t update_bar;
    pfcp_tlv_pfcpsrrsp_flags_t pfcpsrrsp_flags;
    pfcp_tlv_f_seid_t cp_f_seid;
    pfcp_tlv_f_teid_t n4_u_f_teid;
    pfcp_tlv_alternative_smf_ip_address_t alternative_smf_ip_address;
} pfcp_session_report_response_t;



#pragma pack(4)
typedef struct pfcp_message_s {
   pfcp_header_t h;
   union {
        pfcp_heartbeat_request_t pfcp_heartbeat_request;
        pfcp_heartbeat_response_t pfcp_heartbeat_response;
        pfcp_pfd_management_request_t pfcp_pfd_management_request;
        pfcp_pfd_management_response_t pfcp_pfd_management_response;
        pfcp_association_setup_request_t pfcp_association_setup_request;
        pfcp_association_setup_response_t pfcp_association_setup_response;
        pfcp_association_update_request_t pfcp_association_update_request;
        pfcp_association_update_response_t pfcp_association_update_response;
        pfcp_association_release_request_t pfcp_association_release_request;
        pfcp_association_release_response_t pfcp_association_release_response;
        pfcp_version_not_supported_response_t pfcp_version_not_supported_response;
        pfcp_node_report_request_t pfcp_node_report_request;
        pfcp_node_report_response_t pfcp_node_report_response;
        pfcp_session_set_deletion_request_t pfcp_session_set_deletion_request;
        pfcp_session_set_deletion_response_t pfcp_session_set_deletion_response;
        pfcp_session_establishment_request_t pfcp_session_establishment_request;
        pfcp_session_establishment_response_t pfcp_session_establishment_response;
        pfcp_session_modification_request_t pfcp_session_modification_request;
        pfcp_session_modification_response_t pfcp_session_modification_response;
        pfcp_session_deletion_request_t pfcp_session_deletion_request;
        pfcp_session_deletion_response_t pfcp_session_deletion_response;
        pfcp_session_report_request_t pfcp_session_report_request;
        pfcp_session_report_response_t pfcp_session_report_response;
   };
} pfcp_message_t;


typedef struct pfcp_sh
{
	uint8_t seid_presence:1;
	uint8_t mp:1;
	uint8_t spare1:3;
	uint8_t version:3;
} pfcp_sh_t;

void pfcp_message__init();

__si_buff_t * pfcp_build_msg( pfcp_message_t * pfcp_message);
int pfcp_parse_msg( pfcp_message_t * pfcp_message, __si_buff_t * sbuf);
__si_buff_t * pfcp_build__pfcp_association_setup_request( pfcp_association_setup_request_t * pfcp_association_setup_request);

void pfcp__set_request_header( __si_buff_t * pmsg, uint8_t type, uint32_t seqNo, uint8_t seid_presence, uint64_t seid);




#endif


















