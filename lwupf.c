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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "dataplane.h"
#include "sirik_core.h"

// make -f dataplane.m
// export LD_LIBRARY_PATH=.
// gcc -g3 -o lwupf lwupf.c -I.-lpthread libdp.so libsicore.so -Wl,-rpath .
int main( int argc, char* argv[])
{
	__init_sirik_core();
	__si_init_logger( "./logs/");
	
	__si_log( SI_APP_LOG, 0, SI_LOG_CRITICAL, "Initalizing LW-UPF  1.0.0.0 <%s|%s|%d>", __FILE__, __FUNCTION__, __LINE__);
	

	dataplane__init( argc, argv);
	nic_t * access 	= dataplane__addnic( "0000:13:00.0", "192.168.144.13", 1500, 1, 1);
	nic_t * core 	= dataplane__addnic( "0000:1b:00.0", "192.168.144.14", 1500, 1, 1);
	
	dataplane__setPktType( access, 	DATAPLANE__PKT_TYPE__GTP);
	dataplane__setPktType( core, 	DATAPLANE__PKT_TYPE__GI);
	dataplane__set_gatewayip( core, "192.168.144.53");
	dataplane__attach( access, core);
	dataplane__setupNICs();
	

	printf("Started LW-UPF 1.0.0.0\n");
	
	__si_log( SI_APP_LOG, 0, SI_LOG_CRITICAL, "Started LW-UPF 1.0.0.0 <%s|%s|%d>", __FILE__, __FUNCTION__, __LINE__);
	
	while(1) {
		sleep(1);
	}
	return 0;
}