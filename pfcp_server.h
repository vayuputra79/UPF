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

#ifndef __SI__PFCP_STACK2604_H
#define __SI__PFCP_STACK2604_H

#include "sirik_core.h"


typedef struct __si_pfcp_node __si_pfcp_node_t;


typedef struct sess_pdr
{
	struct sess_pdr * next;
	uint32_t pdr_id;
	
} sess_pdr_t;

#define UPLANE__RATING_GROUPS			5


#pragma pack(4)
typedef struct si_up_session
{
	struct up_sess * next;

	__si_pfcp_node_t * node;

	sess_pdr_t * pdrHead;
	sess_pdr_t * pdrCurr;
	pthread_mutex_t pdrLock;

	struct
	{
		uint64_t urr_id;
		uint64_t dl_used;
		uint64_t ul_used;
		uint64_t lt_used;
		uint64_t granted;
	} quota[UPLANE__RATING_GROUPS];
	
	//source-interface: core
	uint32_t ue_ip;
	uint32_t upf_teid;
	uint32_t upf_access_ip;	// on which tpdu / gtpv1 packets will be received
	uint8_t * upipv6[20];
	uint8_t pdn_type;
	
	//forwarding parameters
		// will forward to access
	uint32_t 	outer_header_creation_4;		// GTP-U/UDP/IPv4
	uint32_t 	outer_header_creation_6;		// GTP-U/UDP/IPv6
	uint32_t 	ran_teid;						// outer_header_creation with ran-teid
	uint32_t 	ran_ip;							// outer_header_creation with ran-ip

	//source-interface: access
	//pdr
	uint32_t 	access_outer_header_removal;	// 0 = GTP-U/UDP/IPv4
	uint8_t 	access_qfi;

	uint32_t urseqn;
	
	SI_IndexRow * upf_seid_index_row;
	uint64_t upf_seid;
	uint64_t smf_seid;
	
	uint64_t ul_mbr;
	uint64_t dl_mbr;
	
} __si_up_session_t;






/* 
	max_session_count	= maximum required PFCP sessions
	SEID_begin_no		= begin number of SEID
*/

void __si_pfcp_server__Init( int max_session_count, int SEID_begin_no);
void __si_pfcp_server__SetHost( char * ip, int port);
void __si_pfcp_server__Start();



#endif