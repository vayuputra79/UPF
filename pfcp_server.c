#define _GNU_SOURCE

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
#include <poll.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <sys/resource.h>

#include "tlv.h"
#include "pfcp.h"
#include "plane.h"
#include "pfcp_server.h"
#include "sirik_core.h"


typedef struct __pfcp_server
{
	int Type;						// 1 - Client, 2 - Server
	char IP[50];
	int Port;
	
	// session management
	SI_IndexTable * seidIndexTable;
	si_sirik_pool_t * sessPool;

	int app_type;
	int max_session_count;
	int SEID_begin_no;
	
} __pfcp_server_t;

__pfcp_server_t * pfcp_server = NULL;





void __si_pfcp_server__send__session_establishment_error_response( pfcp_message_t * pfcp_request, __si_pfcp_node_t * node, uint32_t seqNo, uint64_t SEID, int cause)
{
	pfcp_session_establishment_request_t * req = &pfcp_request->pfcp_session_establishment_request;
	
	if( req->cp_f_seid.presence == 1)
	{
		pfcp_f_seid_t * f_seid = (pfcp_f_seid_t *) req->cp_f_seid.data;
		SEID = htobe64( f_seid->seid);
	}
	
	pfcp_message_t pfcp_message;
    pfcp_session_establishment_response_t * response = NULL;
	
	response = &pfcp_message.pfcp_session_establishment_response;
    memset(&pfcp_message, 0, sizeof(pfcp_message_t));

	
    pfcp_node_id_t node_id;
	
	node_id.spare = 0;
    node_id.type = 0;
	node_id.addr = __si_pfcp__getIPv4_addr()->sin_addr.s_addr;

	response->node_id.presence = 1;
    response->node_id.data = &node_id;
    response->node_id.len = 5;
	
	response->cause.presence = 1;
    response->cause.u8 = PFCP_CAUSE_MANDATORY_IE_MISSING;
	
	if( cause == 8) 
	{
		response->cause.u8 = PFCP_CAUSE_REQUEST_REJECTED;
	}
	
	 pfcp_message.h.type = PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE;
    __si_buff_t * pmsg = pfcp_build_msg( &pfcp_message);	
	
	__si_buff__pull( pmsg, 16, 1);
	pfcp__set_request_header( pmsg, PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE, seqNo, 1, SEID);
	
	int sentBytes = __si_pfcp__send_msg( node, pmsg);
}


void __si_pfcp_server__set_ue_ip( pfcp_session_establishment_request_t * req, __si_up_session_t * up_sess)
{
	//UE IP Address will be at Source-Interface Core
	
	int i = 0;
	for( i = 0; i < 3; i++)
	{
		//printf("i=%d pres=%lu\n", i, req->create_pdr[i].presence);
		
		if( req->create_pdr[i].presence == 1)
		{
			pfcp_tlv_create_pdr_t * pdr = &req->create_pdr[i];

			//printf( "presence=%lu u8=%u i=%d \n", pdr->pdi.source_interface.presence,  pdr->pdi.source_interface.u8, i);
			
			if( pdr->pdr_id.presence == 1)
			{
				//printf( "presence=%lu u8=%u i=%d \n", pdr->pdi.source_interface.presence,  pdr->pdi.source_interface.u8, i);
				
				if( pdr->pdi.source_interface.presence == 1 && pdr->pdi.source_interface.u8 == 1)	//Core
				{
					if( pdr->pdi.ue_ip_address.presence == 1)
					{
						char * data = pdr->pdi.ue_ip_address.data;
						
						//printf( "IP BITS=%u\n", data[0] & 0x03);
						
						//if( data[0] & 0x02)
						
						if( (data[0] & 0x03) == 1)
						{
							memcpy( up_sess->upipv6, &data[1], 16);
						}
						else if( (data[0] & 0x03) == 2)
						{
							up_sess->ue_ip = *(uint32_t *)&data[1];
							//printf("UE-IP=%u|%s\n", up_sess->ue_ip, __si_core_convert_inttoipv4( up_sess->ue_ip)); 
							//return;
						}
						else if( (data[0] & 0x03) == 3)
						{
							up_sess->ue_ip = *(uint32_t *)&data[1];
							memcpy( up_sess->upipv6, &data[5], 16);
						}
						
					}
				}
				else if( pdr->pdi.source_interface.presence == 1 && pdr->pdi.source_interface.u8 == 0)	//Access
				{
					if( pdr->pdi.local_f_teid.presence == 1)
					{
						// This Information is of UPF, on which IP it will receive GTP Packet with TEID
						
						char * data = pdr->pdi.local_f_teid.data;
						up_sess->upf_teid = *(uint32_t *)&data[1];
						

						if( data[0] & 0x01)
						{
							//4
							up_sess->upf_access_ip = *(uint32_t *)&data[5];
						}
						else if( data[0] & 0x02)
						{
							//6
						}
						else if( data[0] & 0x03)
						{
							//4n6
							up_sess->upf_access_ip = *(uint32_t *)&data[5];
						}
					}
				}
			}
		}
	}
}



void __si_pfcp_server__set_urr_quota( pfcp_session_establishment_request_t * req, __si_up_session_t * up_sess)
{
	int i = 0;
	for( i = 0; i < 3; i++)
	{
		if( req->create_urr[i].presence == 1)
		{
			pfcp_tlv_create_urr_t * urr = &req->create_urr[i];
			
			if( urr->urr_id.presence == 1 && urr->volume_quota.presence == 1 && urr->volume_quota.len == 9)
			{
				char * d = (char *)urr->volume_quota.data;
				uint64_t data_vol = __si_get_u64( &d[1]);
				
				int j = 0;
				int bFound = 0;
				
				for( j = 0; j < UPLANE__RATING_GROUPS; j++)
				{
					if( urr->urr_id.u32 == up_sess->quota[j].urr_id)
					{
						up_sess->quota[j].granted += data_vol;
						bFound = 1;
						break;
					}
				}
				
				if( bFound == 0)
				{
					for( j = 0; j < UPLANE__RATING_GROUPS; j++)
					{
						if( 0 == up_sess->quota[j].urr_id)
						{
							up_sess->quota[j].urr_id = urr->urr_id.u32;
							up_sess->quota[j].granted += data_vol;
							bFound = 1;
							break;
						}
					}
				}
				
				
			}
		}
	}
}


void __si_pfcp_server__set_urr_update_quota( pfcp_session_modification_request_t * req, __si_up_session_t * up_sess)
{
	int i = 0;
	for( i = 0; i < 3; i++)
	{
		if( req->update_urr[i].presence == 1)
		{
			pfcp_tlv_update_urr_t * urr = &req->update_urr[i];
			
			if( urr->urr_id.presence == 1 && urr->volume_quota.presence == 1 && urr->volume_quota.len == 9)
			{
				char * d = (char *)urr->volume_quota.data;
				uint64_t data_vol = __si_get_u64( &d[1]);
				
				int j = 0;
				int bFound = 0;
				
				for( j = 0; j < UPLANE__RATING_GROUPS; j++)
				{
					if( urr->urr_id.u32 == up_sess->quota[j].urr_id)
					{
						up_sess->quota[j].granted += data_vol;
						bFound = 1;
						break;
					}
				}
				
				if( bFound == 0)
				{
					for( j = 0; j < UPLANE__RATING_GROUPS; j++)
					{
						if( 0 == up_sess->quota[j].urr_id)
						{
							up_sess->quota[j].urr_id = urr->urr_id.u32;
							up_sess->quota[j].granted += data_vol;
							bFound = 1;
							break;
						}
					}
				}
				
				
			}
		}
	}		
}


void __si_pfcp_server__set_access_info( pfcp_session_establishment_request_t * req, __si_up_session_t * up_sess)
{
	int i = 0;
	for( i = 0; i < 3; i++)
	{
		//printf("1\n");
		if( req->create_far[i].presence == 1)
		{
			//printf("2\n");
			pfcp_tlv_create_far_t * far = &req->create_far[i];
			
			if( far->forwarding_parameters.presence == 1 && far->forwarding_parameters.destination_interface.u8 == 0 && far->forwarding_parameters.outer_header_creation.presence == 1)
			{
				//printf("3\n");
				
				if( far->forwarding_parameters.outer_header_creation.data && far->forwarding_parameters.outer_header_creation.len == 10)
				{
					//printf("4  far-index i=%d len=%d\n", i, far->forwarding_parameters.outer_header_creation.len);
					
					char * u8 = (char *)far->forwarding_parameters.outer_header_creation.data;
					
					// printf( "OHC=%02X%02X ", u8[0] & 0xFF, u8[1] & 0xFF);

					// printf( "TEID=%02X%02X%02X%02X ", 
						// u8[2] & 0xFF,
						// u8[3] & 0xFF,
						// u8[4] & 0xFF,
						// u8[5] & 0xFF
					// );
					
					// printf( "IPv4=%02X%02X%02X%02X ", 
						// u8[6] & 0xFF,
						// u8[7] & 0xFF,
						// u8[8] & 0xFF,
						// u8[9] & 0xFF
					// );
					// printf("\n");
						
					if( u8[0] == 0x01 && u8[1] == 0x00)
					{
						// printf( "TEID=%02X%02X%02X%02X ", 
							// u8[2] & 0xFF,
							// u8[3] & 0xFF,
							// u8[4] & 0xFF,
							// u8[5] & 0xFF
						// );
						
						// printf( "IPv4=%02X%02X%02X%02X ", 
							// u8[6] & 0xFF,
							// u8[7] & 0xFF,
							// u8[8] & 0xFF,
							// u8[9] & 0xFF
						// );
						// printf("\n");
					
						up_sess->ran_teid = *(uint32_t *)&u8[2];
					
						uint32_t accessip = *(uint32_t *)&u8[6];
						//printf("AccessIP=%u|%s\n", accessip, __si_core_convert_inttoipv4( accessip)); 
						//up_sess->access_ip = *(uint32_t *)&data[5];
						up_sess->ran_ip = accessip;
						
						// printf("AccessIP=%u|%s|ran-teid=%u|%u\n", accessip, __si_core_convert_inttoipv4( accessip)
							// , up_sess->ran_teid, ntohl(up_sess->ran_teid)); 
					}
				}
			}
		}
	}
}




__si_up_session_t * __si_pfcp_server__session_establishment_request( pfcp_message_t * pfcp_request, __si_pfcp_node_t * node, uint32_t seqNo, uint64_t SEID)
{
	__si_log( SI_APP_LOG, 0, SI_LOG_DEBUG, "session_establishment_request: received request   ip=%s port=%d  %s|%s|%d", node->address, node->port, __FILE__, __FUNCTION__, __LINE__);

	
	pfcp_session_establishment_request_t * req = &pfcp_request->pfcp_session_establishment_request; 
	
	if( req->node_id.presence == 0)
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_ERROR, "session_establishment_request: node_id is missing   ip=%s port=%d  %s|%s|%d", node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
		__si_pfcp_server__send__session_establishment_error_response( pfcp_request, node, seqNo, SEID, 1);
		return NULL;
	}
	
	if( req->cp_f_seid.presence == 0)
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_ERROR, "session_establishment_request: f_seid is missing   ip=%s port=%d  %s|%s|%d", node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
		__si_pfcp_server__send__session_establishment_error_response( pfcp_request, node, seqNo, SEID, 2);
		return NULL;		
	}
	
	if( req->create_pdr[0].presence == 0)
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_ERROR, "session_establishment_request: pdr-0 is missing   ip=%s port=%d  %s|%s|%d", node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
		__si_pfcp_server__send__session_establishment_error_response( pfcp_request, node, seqNo, SEID, 3);
		return NULL;		
	}

	if( req->create_pdr[1].presence == 0)
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_ERROR, "session_establishment_request: pdr-1 is missing   ip=%s port=%d  %s|%s|%d", node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
		__si_pfcp_server__send__session_establishment_error_response( pfcp_request, node, seqNo, SEID, 4);
		return NULL;		
	}
	
	if( req->create_far[0].presence == 0)
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_ERROR, "session_establishment_request: far-0 is missing   ip=%s port=%d  %s|%s|%d", node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
		__si_pfcp_server__send__session_establishment_error_response( pfcp_request, node, seqNo, SEID, 5);
		return NULL;		
	}

	if( req->create_far[1].presence == 0)
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_ERROR, "session_establishment_request: far-1 is missing   ip=%s port=%d  %s|%s|%d", node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
		__si_pfcp_server__send__session_establishment_error_response( pfcp_request, node, seqNo, SEID, 6);
		return NULL;		
	}
	
	pfcp_f_seid_t * req_f_seid = (pfcp_f_seid_t *) req->cp_f_seid.data;
	__si_up_session_t * sess = NULL;

	pfcp_message_t pfcp_message;
    pfcp_session_establishment_response_t * response = NULL;
	
	response = &pfcp_message.pfcp_session_establishment_response;
    memset(&pfcp_message, 0, sizeof(pfcp_message_t));

	
    pfcp_node_id_t node_id;
	
	node_id.spare = 0;
    node_id.type = 0;
	node_id.addr = __si_pfcp__getIPv4_addr()->sin_addr.s_addr;

	response->node_id.presence = 1;
    response->node_id.data = &node_id;
    response->node_id.len = 5;




	sess = (__si_up_session_t *) __si_pool_allocate( pfcp_server->sessPool);
	memset( sess, 0, sizeof(__si_up_session_t));
	
	sess->upf_seid_index_row = __si_IndexTable_getRow( pfcp_server->seidIndexTable);
	
	if(!sess->upf_seid_index_row)
	{
		__si_pool_release( (uint8_t*)sess);
		__si_log( SI_APP_LOG, 0, SI_LOG_DEBUG, "session_establishment_request:  failed seidIndexTable exausted,   %s|%s|%d", __FILE__, __FUNCTION__, __LINE__);
		__si_pfcp_server__send__session_establishment_error_response( pfcp_request, node, seqNo, SEID, 6);
		return NULL;
	}
	
	
	sess->upf_seid = __si_indexRow_getId( sess->upf_seid_index_row);
	__si_indexRow_setObject( sess->upf_seid_index_row, (uint8_t*)sess);
	
	
	//
	pfcp_f_seid_t f_seid;
	
	f_seid.spare 	= 0;
    f_seid.ipv4 	= 1;
    f_seid.ipv6 	= 0;
	f_seid.seid 	= htobe64( sess->upf_seid);		//htobe64( sess->seid);
	f_seid.addr 	= __si_pfcp__getIPv4_addr()->sin_addr.s_addr;	
	response->up_f_seid.presence = 1;
    response->up_f_seid.data = &f_seid;
    response->up_f_seid.len = 13;
	
	response->cause.presence = 1;
    response->cause.u8 = PFCP_CAUSE_REQUEST_ACCEPTED;


	pfcp_tlv_created_pdr_t * pdr = NULL;
	
	pdr = &response->created_pdr[0];
	pdr->presence = 1;
	pdr->pdr_id.presence = 1;
	pdr->pdr_id.u16 = req->create_pdr[0].pdr_id.u16;
	
	pdr = &response->created_pdr[1];
	pdr->presence = 1;
	pdr->pdr_id.presence = 1;
	pdr->pdr_id.u16 = req->create_pdr[1].pdr_id.u16;
	
	//sess->pdn_type
	if(req->pdn_type.presence == 1)
	{
		sess->pdn_type = req->pdn_type.u8;
	}
	
	//printf( "pdn_type=%u  %s|%d\n", sess->pdn_type, __FUNCTION__, __LINE__);

	sess->smf_seid = htobe64( req_f_seid->seid);
	__si_pfcp_server__set_ue_ip( req, sess);
	__si_pfcp_server__set_access_info( req, sess);
	__si_pfcp_server__set_urr_quota( req, sess);
	

	sess->urseqn = 0;
	sess->node = node;
	

	//__si_power_table_add_lk( node->sessionTable, htobe64(req_f_seid->seid), (uint8_t *)sess);
	__si_power_table_add_lk( node->teidTable, sess->upf_teid, (uint8_t *)sess);
	

	char upf_access_ip[20];
	memset( upf_access_ip, 0, sizeof( upf_access_ip));
	
	char * ip = __si_core_convert_inttoipv4( sess->upf_access_ip);
	strcpy( upf_access_ip, ip);

	char c_ue_ip[20];
	memset( c_ue_ip, 0, sizeof(c_ue_ip));
	
	ip = __si_core_convert_inttoipv4( sess->ue_ip);
	strcpy( c_ue_ip, ip);
	

	__si_log( SI_APP_LOG, 0, SI_LOG_DEBUG, "PFCP UPF-SEId=%lu  SMF-SEID=%lu  upf_teid=%u|%u  UPF-ACCESS-IP=%u[%s]  UE-IP=%u[%s]   %s|%d", 
		sess->upf_seid, sess->smf_seid, sess->upf_teid, htonl(sess->upf_teid), sess->upf_access_ip, upf_access_ip, sess->ue_ip, c_ue_ip, __FILE__, __LINE__);


	 pfcp_message.h.type = PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE;
    __si_buff_t * pmsg = pfcp_build_msg( &pfcp_message);	
	
	__si_buff__pull( pmsg, 16, 1);
	pfcp__set_request_header( pmsg, PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE, seqNo, 1, htobe64(req_f_seid->seid));


	int sentBytes = __si_pfcp__send_msg( node, pmsg);
	
	if( sentBytes <= 0) 
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_ERROR, "session_establishment_request: sending message failed  sentBytes=%d  ip=%s port=%d  %s|%s|%d", sentBytes, node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
	
		__si_IndexTable_putRow( sess->upf_seid_index_row);
		__si_pool_release( (uint8_t*)sess);
		return NULL;
	} 
	else {
		__si_log( SI_APP_LOG, 0, SI_LOG_DEBUG, "session_establishment_request: sending message successful  sentBytes=%d  ip=%s port=%d  %s|%s|%d", sentBytes, node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
	}

	return sess;
}


__si_up_session_t * __si_pfcp_server__session_modification_request( pfcp_message_t * pfcp_request, __si_pfcp_node_t * node, uint32_t seqNo, uint64_t SEID)
{
	__si_log( SI_APP_LOG, 0, SI_LOG_DEBUG, "session_modification_request: received request   ip=%s port=%d  %s|%s|%d", node->address, node->port, __FILE__, __FUNCTION__, __LINE__);

	
	pfcp_session_modification_request_t * req = &pfcp_request->pfcp_session_modification_request;
	
	__si_up_session_t * sess = NULL;
	SI_IndexRow * indexRow = __si_IndexTable_FindRow( pfcp_server->seidIndexTable, (uint32_t)SEID);
	
	if( indexRow)
	{
		sess = (__si_up_session_t*)__si_indexRow_getObject( indexRow);
	}
	else
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_ERROR, "session_modification_request: pfcp session not found with upf-seid=%lu   ip=%s port=%d  %s|%s|%d", SEID, node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
		return NULL;
	}
	
	
	if( sess)
	{
		if( req->update_far[0].presence == 1)
		{
			if( req->update_far[0].update_forwarding_parameters.presence == 1)
			{
				if( req->update_far[0].update_forwarding_parameters.outer_header_creation.presence == 1)
				{
					if( req->update_far[0].update_forwarding_parameters.outer_header_creation.len == 10)
					{
						char * data = (char *)req->update_far[0].update_forwarding_parameters.outer_header_creation.data;
						
						sess->ran_teid = htonl( *(uint32_t *)&data[2]);


						if( data[0] & 0x01)
						{
							//4
							sess->ran_ip = *(uint32_t *)&data[6];
						}
						else if( data[0] & 0x02)
						{
							//6
						}
						else if( data[0] & 0x03)
						{
							//4n6
							sess->ran_ip = *(uint32_t *)&data[6];
						}

						char c_ran_ip[20];
						memset( c_ran_ip, 0, sizeof( c_ran_ip));
						__si_core_convert_inttoipv4_2( sess->ran_ip, c_ran_ip);

						
						__si_log( SI_APP_LOG, 0, SI_LOG_ERROR, "session_modification_request: updated ran_info ran-teid=%u  ran-ip=%s|%u   ip=%s port=%d  %s|%s|%d", 
							sess->ran_teid, c_ran_ip, sess->ran_ip, node->address, node->port, __FILE__, __FUNCTION__, __LINE__);


					}
				}
			}
		}
		
		__si_pfcp_server__set_urr_update_quota( req, sess);

		

		pfcp_message_t pfcp_message;
		pfcp_session_modification_response_t * response = NULL;
		
		response = &pfcp_message.pfcp_session_modification_response;
		memset(&pfcp_message, 0, sizeof(pfcp_message_t));

		response->cause.presence = 1;
		response->cause.u8 = PFCP_CAUSE_REQUEST_ACCEPTED;
		
		 pfcp_message.h.type = PFCP_SESSION_MODIFICATION_RESPONSE_TYPE;
		__si_buff_t * pmsg = pfcp_build_msg( &pfcp_message);	
		
		__si_buff__pull( pmsg, 16, 1);
		pfcp__set_request_header( pmsg, PFCP_SESSION_MODIFICATION_RESPONSE_TYPE, seqNo, 1, sess->smf_seid);
		
		int sentBytes = __si_pfcp__send_msg( node, pmsg);
		
		if( sentBytes <= 0) 
		{
			__si_log( SI_APP_LOG, 0, SI_LOG_ERROR, "session_modification_request: sending message failed  sentBytes=%d  ip=%s port=%d  %s|%s|%d", sentBytes, node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
		} 
		else 
		{
			__si_log( SI_APP_LOG, 0, SI_LOG_DEBUG, "session_modification_request: sending message successful  sentBytes=%d  ip=%s port=%d  %s|%s|%d", sentBytes, node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
		}

		return sess;
	}	
	return NULL;
}


__si_up_session_t * __si_pfcp_server__session_delete_request( pfcp_message_t * pfcp_request, __si_pfcp_node_t * node, uint32_t seqNo, uint64_t SEID)
{
	uint64_t cp_seid = 0;
	
	__si_up_session_t * sess = NULL;
	SI_IndexRow * indexRow = __si_IndexTable_FindRow( pfcp_server->seidIndexTable, (uint32_t)SEID);
	
	if( indexRow)
	{
		sess = (__si_up_session_t*)__si_indexRow_getObject( indexRow);
		
		if( sess)
		{
			cp_seid = sess->smf_seid;
			__si_IndexTable_putRow( indexRow);
			sess->upf_seid_index_row = NULL;
			
			__si_pool_release( (uint8_t*)sess);
		}
	}
	
	
	if(cp_seid == 0)
	{
		// we cannot send error because, we dont know CP-SEID
		__si_log( SI_APP_LOG, 0, SI_LOG_ERROR, "session_delete_request: pfcp session not found with upf-seid=%lu   ip=%s port=%d  %s|%s|%d", SEID, node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
		return NULL;
	}
	
	
	pfcp_session_deletion_request_t * req = &pfcp_request->pfcp_session_deletion_request; 
	
	pfcp_message_t pfcp_message;
    pfcp_session_deletion_response_t * response = NULL;
	
	response = &pfcp_message.pfcp_session_deletion_response;
    memset(&pfcp_message, 0, sizeof(pfcp_message_t));

	response->cause.presence = 1;
	response->cause.u8 = PFCP_CAUSE_REQUEST_ACCEPTED;



	 pfcp_message.h.type = PFCP_SESSION_DELETION_RESPONSE_TYPE;
    __si_buff_t * pmsg = pfcp_build_msg( &pfcp_message);	
	
	__si_buff__pull( pmsg, 16, 1);
	pfcp__set_request_header( pmsg, PFCP_SESSION_DELETION_RESPONSE_TYPE, seqNo, 1, cp_seid);

	
	int sentBytes = __si_pfcp__send_msg( node, pmsg);

	if( sentBytes <= 0) 
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_ERROR, "session_delete_request: sending message failed  sentBytes=%d  ip=%s port=%d  %s|%s|%d", sentBytes, node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
	} 
	else 
	{
		__si_log( SI_APP_LOG, 0, SI_LOG_DEBUG, "session_delete_request: sending message successful  sentBytes=%d  ip=%s port=%d  %s|%s|%d", sentBytes, node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
	}
	
	return NULL;
}


__si_up_session_t * __si_pfcp_server__session_report_response( pfcp_message_t * pfcp_request, __si_pfcp_node_t * node, uint32_t seqNo, uint64_t SEID)
{
	uint64_t cp_seid = 0;
	
	__si_up_session_t * sess = NULL;
	SI_IndexRow * indexRow = __si_IndexTable_FindRow( pfcp_server->seidIndexTable, (uint32_t)SEID);
	
	if( indexRow)
	{
		sess = (__si_up_session_t*)__si_indexRow_getObject( indexRow);
		
		if( sess)
		{
			cp_seid = sess->smf_seid;
			__si_IndexTable_putRow( indexRow);
			sess->upf_seid_index_row = NULL;
			
			__si_pool_release( (uint8_t*)sess);
		}
	}
	
	
	if(cp_seid == 0)
	{
		// we cannot send error because, we dont know CP-SEID
		__si_log( SI_APP_LOG, 0, SI_LOG_ERROR, "session_delete_request: pfcp session not found with upf-seid=%lu   ip=%s port=%d  %s|%s|%d", SEID, node->address, node->port, __FILE__, __FUNCTION__, __LINE__);
		return NULL;
	}
	
	return sess;
}






void __si_pfcp_server__onmsg( pfcp_message_t * pfcp_request, __si_pfcp_node_t * pNode, uint32_t seqNo, uint64_t SEID)
{
	__si_up_session_t * sess = NULL;
	switch( pfcp_request->h.type)
	{
		case PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE:
			{
				sess = __si_pfcp_server__session_establishment_request( pfcp_request, pNode, seqNo, SEID);
			}
			break;
		case PFCP_SESSION_MODIFICATION_REQUEST_TYPE:
			{
				sess = __si_pfcp_server__session_modification_request( pfcp_request, pNode, seqNo, SEID);
			}
			break;
		case PFCP_SESSION_DELETION_REQUEST_TYPE:
			{
				sess = __si_pfcp_server__session_delete_request( pfcp_request, pNode, seqNo, SEID);
			}
			break;
		case PFCP_SESSION_REPORT_RESPONSE_TYPE:
			{
				sess = __si_pfcp_server__session_report_response( pfcp_request, pNode, seqNo, SEID);
			}
			break;
		default:
			{
				__si_log( SI_APP_LOG, 0, SI_LOG_CRITICAL, "pfcp-message unhandled message with type=%d   %s|%s|%d", 
					pfcp_request->h.type, __FILE__, __FUNCTION__, __LINE__);
			}
			break;
	}	
}







void __si_pfcp_server__Init( int max_session_count, int SEID_begin_no)
{
	if(!pfcp_server)
	{
		pfcp_server = (__pfcp_server_t*)malloc(sizeof(__pfcp_server_t));
		memset( pfcp_server, 0, sizeof(__pfcp_server_t));
		
		pfcp_server->max_session_count = max_session_count;
		pfcp_server->SEID_begin_no = SEID_begin_no;

		
		if( pfcp_server->SEID_begin_no == 0)
		{
			pfcp_server->SEID_begin_no = 1;
		}
		
		if( pfcp_server->max_session_count == 0)
		{
			pfcp_server->max_session_count = 100;
		}
	}
}


void __si_pfcp_server__SetHost( char * ip, int port)
{
	strcpy( pfcp_server->IP, ip);
	pfcp_server->Port = port;
}


void __si_pfcp_server__Start()
{
	// uid_t uid = getuid();
	// if( uid != 0)
	// {
		// printf( "run with root user\n");
		// exit(0);
	// }
	
	if( strlen( pfcp_server->IP) == 0)
	{
		printf("printf PFCP Host IP Not Configured\n");
		exit(0);
	}

	if( pfcp_server->Port == 0)
	{
		printf("printf PFCP Host Port Not Configured\n");
		exit(0);
	}
	
	__si_pfcp__setOnPfcpMsg( __si_pfcp_server__onmsg);
	pfcp_message__init();

	__si_pfcp__initalize( 2, pfcp_server->Port, 4, pfcp_server->IP, 0, pfcp_server->IP);

	pfcp_server->sessPool 			= __si_pool_create( "sessPool", sizeof(__si_up_session_t), pfcp_server->max_session_count, 1);
	pfcp_server->seidIndexTable		= __si_IndexTable_create( 2001, pfcp_server->max_session_count);
}



