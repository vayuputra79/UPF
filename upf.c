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


#include "sirik_core.h"
#include "pfcp_server.h"

int main( int argc, char **argv)
{
	__init_sirik_core();
	__si_init_logger("./logs/");
	__si_buff__init();
	
	__si_pfcp_server__Init( 1000, 2001);
	__si_pfcp_server__SetHost( "192.160.1.5", 8805);
	__si_pfcp_server__Start();	

	__si_core_wait();
	return 0;	
}