#include <stdio.h>
#include <stdlib.h>


#ifndef DATAPLANE_H
#define DATAPLANE_H


#define   DATAPLANE__PKT_TYPE__GI				1
#define   DATAPLANE__PKT_TYPE__GTP				2
#define   DATAPLANE__PKT_TYPE__GTP_PDCP			3

typedef struct nic nic_t;

void dataplane__init( int argc, char **argv);
nic_t * dataplane__addnic( unsigned char * sDevice, char * sIPv4, int mtu, int requiredReceiveQueueCount, int requiredSendQueueCount);
void dataplane__setPktType( nic_t *, int pkt_type);
void dataplane__setupNICs();
void dataplane__attach( nic_t * , nic_t *);
void dataplane__set_gatewayip( nic_t * nic, char * gatewayip);
void dataplane__set_core_counts( nic_t *, int recv_core_count, int recv_worker_core_count, int send_core_count, int send_worker_core_count);
void dataplane__start();





#endif



