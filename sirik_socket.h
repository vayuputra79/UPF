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
#include <resolv.h>

#if TLS_SOCKET_SUPPORT
	#include "openssl/ssl.h"
	#include "openssl/err.h"
#endif

#include "sirik_core.h"

#ifndef SIRIK_SERVER_H
#define SIRIK_SERVER_H

#define SIRIK_TRANSPORT_TYPE_TCP 			1
#define SIRIK_TRANSPORT_TYPE_UDP 			2
#define SIRIK_TRANSPORT_TYPE_SCTP 			3

#define SIRIK_IP_VERSION_4 					4
#define SIRIK_IP_VERSION_6 					6

#define SIRIK_READ_MODE_DEDICATED 			1
#define SIRIK_READ_MODE_SHARED 				2

#define 	SIRIK_SOCKET_BUFFER_SIZE					1520
#define 	SIRIK_SOCKET_UDP_BUFFER_SIZE				1520
#define 	SIRIK_SOCKET_SCTP_BUFFER_SIZE				5000

#if USR_SCTP_SUPPORT
	#include <usrsctp.h>
#endif


typedef struct __si_socket_engine SI_SocketEngine;
typedef struct __si_socket SI_Socket;
typedef struct __si_socket_thread SI_SocketThread;
typedef struct __si_socket_buffer SI_SocketBuffer;
typedef struct __si_socket_udp_buffer SI_SocketUdpBuffer;

typedef SI_Socket * (*si_fp_create_server_socket)( char * ip, int ipversion, int transportType, int port, int tls, char * cert, char * pKey);
typedef SI_Socket * (*si_fp_accept_client_socket)( SI_Socket * parent, int fd, void * cli_addr, int cli_len);
typedef void (*si_fp_create_client_socket)( char * ip, int ipversion, int transportType, int port, int tls, SI_Socket **);
typedef void (*si_fp_close_socket)( SI_Socket *);
typedef int (*si_fp_connect_socket)( SI_Socket *);
typedef void (*si_fp_socket_event_on_accept)( SI_Socket *, SI_Socket *);
typedef void (*si_fp_socket_event_on_close)( SI_Socket *);
typedef void (*si_fp_socket_event_on_buffer)( SI_Socket *);
typedef void (*si_fp_socket_event_lock)( SI_Socket *);
typedef void (*si_fp_add_socket_buffer)( SI_SocketBuffer *);
typedef void (*si_fp_add_socket_udp_packet)( SI_SocketUdpBuffer *);

typedef void (*si_fp_start_socket_engine)();
typedef void (*si_fp_start_server_socket)( SI_Socket *);
typedef void (*si_fp_tcp_read_socket_data)( SI_Socket *, SI_SocketThread *);
typedef int (*si_fp_socket_send_data)( SI_Socket *, char * buff, int len, int tryCount);
typedef int (*si_fp_tcp_get_buffer)( SI_Socket * siSocket, char * data, int length);
typedef void (*si_fp_socket_generic_event)( SI_Socket *);
typedef int (*si_fp_socket_is_ip_allowed)( char * ip, int iplen, int ver, int port);

#pragma pack(4)
typedef struct __si_ipaddress
{
	uint8_t IPVersion;
	int Port;
	char IPAddress[17];
} SI_IPAddress;

#pragma pack(4)
typedef struct __si_socket_thread
{
	struct __si_socket_thread * Next;
	pthread_t id;
	
	int is_epoll_thread;
	int is_poll_thread;
	
	int epoll_fd;
	int poll_fd;
	int index;
	int count;
	pthread_mutex_t CountLock;
	
	int LastReads;
	long int LastTotalReads;
	long int TotalReads;
	
	int isActive;
	int isHost;
	sem_t sem_lock;
	int fd;
	//struct sockaddr_in clientaddr;
	uint8_t clientaddrbuff[200];
	int addrlen;
	
	
	int epollSocketFdCount;
	pthread_mutex_t epollSocketFdCountLock;
	
	/*	u = unsigned	*/
	uint8_t * usiSocket;	
} SI_SocketThread;

#pragma pack(4)
typedef struct __si_socket_buffer
{
	struct __si_socket_buffer * Next;

	char buff[SIRIK_SOCKET_BUFFER_SIZE];
	int pos;
	int len;
	
	SI_Socket * siSocket;
	uint8_t isReleased;
	
} SI_SocketBuffer;

#pragma pack(4)
typedef struct __si_socket_udp_buffer
{
	struct __si_socket_udp_buffer * Next;

	struct sockaddr_in clientaddr;
	struct sockaddr_in6 clientaddr6;
	socklen_t clientlen;
	
	char buff[SIRIK_SOCKET_UDP_BUFFER_SIZE];
	int pos;
	int len;
	
	SI_Socket * siSocket;
	uint8_t isReleased;
	
} SI_SocketUDPBuffer;

#pragma pack(4)
typedef struct __si_socket_sctp_buffer
{
	struct __si_socket_sctp_buffer * Next;

	char buff[SIRIK_SOCKET_SCTP_BUFFER_SIZE];
	int pos;
	int len;
	
	struct sockaddr_in clientaddr;
	struct sockaddr_in6 clientaddr6;
	socklen_t clientlen;
	
	SI_Socket * siSocket;
	uint8_t isReleased;
	SI_SocketThread * siThread;
	
	uint16_t streamId;
	uint16_t ppid;
} SI_SocketSCTPBuffer;

#pragma pack(4)
typedef struct __si_socket_async_buffer
{
	struct __si_socket_async_buffer * Next;
	
	char * buff;
	int len;
	SI_Socket * siSocket;
	
} SI_SocketAyncBuffer;

#pragma pack(4)
typedef struct __si_socket
{
	struct __si_socket * SENext;	//for Socket Engine epoll async
	
	struct __si_socket * Next;		//for Pool
	struct __si_socket * Parent;	//for Parent if it is Host	

	struct __si_socket * ChildHead;			//for Pool
	struct __si_socket * ChildCurrent;		//for Pool
	int ChildSocketCount;
	pthread_mutex_t ChildLock;
	
	pthread_mutex_t CloseLock;
	pthread_mutex_t ConnectLock;
	
	int UseEPoll;
	int isListner;
	int id;
	int fd;
	int isConnected;
	int disableClientAutoReConnect;
	int isActive;
	int isFree;
	int GenId;
	int isHost;	
	int isStarted;
	int TlsEnabled;
	int TlsAyncWrite;
	int StateFull;
	int noDelay;							//default 0
	char host[17];
	
	int epoll_fd;
	SI_SocketAyncBuffer * AyncWriteBufferHead;
	SI_SocketAyncBuffer * AyncWriteBufferCurrent;
	pthread_mutex_t AsyncWriteLock;
	
	#if TLS_SOCKET_SUPPORT
		SSL * ssl;
		SSL_CTX * ctx;
		pthread_mutex_t ioLock;
	#endif

	#if USR_SCTP_SUPPORT
		struct socket * sock;
	#endif
	
	int    ai_family;
	struct sockaddr_in cli_addr;
	struct sockaddr_in6 cli_addr6;	
	int cli_len;
	unsigned char ClientConnectionId[40];		//CLIENTIP_PROTOCOLID_PORT
	
	uint8_t TransportType;			//TCP/UDP/SCTP
	
	SI_IPAddress IPAddresses[4];
	uint8_t IPAddressCount;
	
	int IPVersion;				//V4/V6
	uint32_t IPPort;				
	
	SI_IPAddress ClientIP;
	uint32_t CIPPort;
	
	SI_IPAddress RemoteIPAddresses[4];
	uint8_t RemoteIPAddressCount;
	uint32_t RemoteIPPort;				// when connecting to server connect on specific port
	
	long int TimerTick;
	
	int LastReads;
	int LastWrites;
	int ReadInProgress;
	int ReadSignal;
	
	long int TotalReads;
	long int TotalWrites;

	uint16_t max_o_streams;		// used for configuring
	uint16_t max_i_streams;		// used for configuring
	uint32_t PPID;

	uint16_t last_o_streams;
	uint16_t peer_max_o_streams;	//received from sctp stack
	uint16_t peer_max_i_streams;	//received from sctp stack
	
	uint64_t BeforeMessageSend;
	uint64_t AfterMessageSent;
	uint64_t ReceivedMessages;
	
	uint64_t LastMessageSent;
	uint64_t LastReceivedMessages;

	int UseSendLock;
	pthread_mutex_t SendLock;
	
	
	SI_SocketSCTPBuffer * SctpBufferHead;
	SI_SocketSCTPBuffer * SctpBufferCurrent;
	
	SI_SocketUdpBuffer * UdpBufferHead;
	SI_SocketUdpBuffer * UdpBufferCurrent;
	
	SI_SocketBuffer * BufferHead;
	SI_SocketBuffer * BufferCurrent;
	pthread_mutex_t BufferLock;
	pthread_mutex_t BufferReadLock;
	int BufferLength;
	int BufferPacketCount;
	
	socklen_t clientlen;
	
	SI_SocketThread * epollThread;
	int UnknownSCTPEventCount;
	
	//using for sctp socket, when connected to server as client
	SI_SocketThread * clientReadThread;
	
	uint8_t * parentData1;
	uint8_t * transportEng;
	si_fp_socket_event_on_accept OnAccept;
	si_fp_socket_event_on_close OnClose;
	si_fp_socket_event_on_buffer OnBufferReceive;
	si_fp_add_socket_udp_packet OnUdpPacketReceive;
	int OnCloseFired;
	pthread_mutex_t OnCloseLock;
	
	si_fp_accept_client_socket Accept;
	si_fp_socket_send_data Send;
	si_fp_tcp_read_socket_data Read;
	si_fp_close_socket Close;
	si_fp_connect_socket Connect;
	si_fp_connect_socket OnConnected;	
	si_fp_add_socket_buffer AddBuffer;
} SI_Socket;

void __si_socket_engine___set_sctp_epoll_thread_count( int num);
void __si_socket_engine_add_socket_to_engine_for_epoll_async( SI_Socket * siSocket);

#pragma pack(4)
typedef struct __si_socket_engine
{
	void * queueSctpSocketBufferPoolObject;
	
	SI_Socket * SocketEPollAyncWriteHead;
	SI_Socket * SocketEPollAyncWriteCurrent;
	pthread_mutex_t SocketAyncWriteLock;
	
	int MaxClients;
	int MaxTpsPerClient;
	
	char AllowedIPs[100][20];
	int AllowedIPCount;

	char BlockedIPs[100][20];
	int BlockedIPCount;

	int SocketClosedCount;
	
	pthread_mutex_t SocketConnectLock;
	
	char CertPath[249];
	char CertKeyPath[249];	
	
	SI_SocketBuffer	  * BufferQueueLineHead;
	SI_SocketBuffer   * BufferQueueLineCurrent;
	int 				BufferQueueLineThreadCount;
	int					BufferQueueLineCount;
	long int 			BufferQueueLineTotalQueuedCount;
	pthread_mutex_t 	BufferQueueLineLock;	
	sem_t				buffer_queue_sem_lock;	
	
	
	//current configured sockets
	SI_Socket * SocketHead;
	SI_Socket * SocketCurrent;
	pthread_mutex_t SocketLock;
	
	//created sockets which are unused, new accepts can take from this
	SI_Socket * SocketPoolHead;
	SI_Socket * SocketPoolCurrent;	
	pthread_mutex_t SocketPoolLock;	
	
	si_fp_create_server_socket CreateServerSocket;
	si_fp_create_client_socket CreateClientSocket;
	
	si_fp_start_server_socket Start;	
	si_fp_start_socket_engine StartEngine;
	
	si_fp_socket_event_lock ReadLock;
	si_fp_socket_event_lock ReadUnLock;
	si_fp_connect_socket GetBufferLength;
	si_fp_tcp_get_buffer GetBuffer;
	si_fp_tcp_get_buffer GetInspectionBuffer;
	si_fp_socket_generic_event ReleaseUsedBuffer;
	
	SI_SocketBuffer * BufferPoolHead;
	SI_SocketBuffer * BufferPoolCurrent;
	int TotalBufferPoolCount;
	int AvailableBufferPoolCount;
	int UsedBufferPoolCount;	
	pthread_mutex_t BufferPoolLock;

	SI_SocketUdpBuffer * UdpBufferPoolHead;
	SI_SocketUdpBuffer * UdpBufferPoolCurrent;
	int UdpTotalBufferPoolCount;
	int UdpAvailableBufferPoolCount;
	int UdpUsedBufferPoolCount;	
	pthread_mutex_t UdpBufferPoolLock;
	
	SI_SocketSCTPBuffer * SctpBufferPoolHead;
	SI_SocketSCTPBuffer * SctpBufferPoolCurrent;
	int SctpTotalBufferPoolCount;
	int SctpAvailableBufferPoolCount;
	int SctpUsedBufferPoolCount;	
	pthread_mutex_t SctpBufferPoolLock;
	
	SI_SocketThread * ThreadHead;
	SI_SocketThread * ThreadCurrent;
	pthread_mutex_t ThreadLock;	
	
	SI_SocketThread * lkSctpThreadHead;
	SI_SocketThread * lkSctpThreadCurrent;
	pthread_mutex_t lkSctpThreadLock;
	
	SI_SocketThread * lkEpollSctpThreadHead;
	SI_SocketThread * lkEpollSctpThreadCurrent;
	pthread_mutex_t lkEpollSctpThreadLock;	
	int InitialEPollThreads;
	int InitialSCTPEPollThreads;
	

	SI_SocketThread * lkPollSctpThreadHead;
	SI_SocketThread * lkPollSctpThreadCurrent;
	pthread_mutex_t lkPollSctpThreadLock;
	SI_Socket * lkPollLastPolledSocket;
	SI_Socket * lkPollLastPolledSignalSocket;
	int InitialPollThreads;
	int PollThreadsCount;

	int TotalSocketsCount;
	int EPollThreadsCount;
	int MaxSocketsPerEPoll;
	
	
	
	long int TlsTotalReadContinueCount;
	long int TlsTotalWriteContinueCount;
	
	void * bufferQueue;
} SI_SocketEngine;


extern SI_SocketEngine * __si_socketEngine;

void __si_socket_engine_init();

SI_SocketBuffer * __si_socket_engine_allocate_socket_buffer();
void __si_socket_engine_release_socket_buffer( SI_SocketBuffer *);
void __si_socket_engine_create_socket_buffer( int size, int inlockMode);
void __si_socket_engine_add_socket_buffer_to_pool( SI_SocketBuffer *, int inlockMode);
int __si_socket_engine_tcp_get_buffer( SI_Socket * siSocket, char * data, int length);


SI_Socket * __si_socket_engine__udp4_start_socket( char * ip, int port, si_fp_add_socket_udp_packet OnUdpPacketReceive);


void __si_socket_engine_print_stats();
void __si_socket_engine_init_tls();
void __si_socket_engine__set_sendlock( SI_Socket * siSocket, int i);

void __si_socket_engine_tcp_tls_print_ssl_error_codes();

void __si_socket_engine_tcp_release_socket_head_packet( SI_Socket * siSocket);
void __si_socket_engine_tcp_release_socket_all_packets( SI_Socket * siSocket);

#pragma pack(4)
typedef struct __si_sctp_socket_info
{
	int ipCount;
	int ipVersion;
	int Port;
	char IP[10][50];			//Local-Address
	
	int RemotePort;					
	int RemoteIpCount;
	char RemoteIP[10][50];		//where client will call connect
	uint32_t PPID;
	
	int UseEPoll;
	uint16_t MaxOStreams;
	uint16_t MaxIStreams;
	
} SI_SctpSocketInfo;

//sctp changes
SI_Socket * __si_socket_engine_create_sctp_server_socket( SI_SctpSocketInfo * sctpSocketInfo);
SI_Socket * __si_socket_engine_create_sctp_client_socket( SI_SctpSocketInfo * sctpSocketInfo);
int __si_socket_engine_sctp_connect_socket( SI_Socket * siSocket);
int __si_socket_engine_sctp_send( SI_Socket * siSocket, char * buffer, int len);
int __si_socket_engine_sctp_send_ngap( SI_Socket * siSocket, char * buffer, int len);
int __si_socket_engine_sctp_send2( SI_Socket * siSocket, char * buffer, int len, uint16_t streamInfo, uint32_t ppid);

SI_SocketSCTPBuffer * __si_socket_engine_allocate_sctp_socket_buffer();
void __si_socket_engine_release_sctp_socket_buffer( SI_SocketSCTPBuffer * socketBuffer);
void __si_socket_engine_create_sctp_socket_buffer( int size, int inlockMode);
void __si_socket_engine_add_sctp_socket_buffer_to_pool( SI_SocketSCTPBuffer * socketBuffer, int inlockMode);

void __si_socket_engine_release_socket_udp_buffer( SI_SocketUdpBuffer * socketBuffer);
int __si_socket_engine_udp_send_response( int fd, struct sockaddr * saddr, int slen, char * buff, int len);
void __si_socket_engine_sctp_client_socket_start_read_thread( SI_Socket * siSocket);

void __si_socket_engine_run_statefull_client_socket( SI_Socket * cSocket );
void __si_socket_create_client_object( char * ip, int ipversion, int transportType, int port, int tls, SI_Socket ** cSocket);

uint16_t __si_socket_sctp_next_streamid( uint8_t skipzero, SI_Socket * siSocket);
void __si_socket_engine_sctp__close_client_connection( SI_Socket * siSocket);
int __si_socket_engine_tcp_get_sample_buffer( SI_Socket * siSocket, char * data, int length);

void  __si_socket_engine__set_is_ip_allowed_cb( si_fp_socket_is_ip_allowed a);

int __si_socket_engine_get_fd( SI_Socket * siSocket);
int __si_socket_engine_is_connected( SI_Socket * siSocket);
int __si_socket_engine_is_active( SI_Socket * siSocket);

void __si_socket_engine_create_client_socket2( char * ip, int ipversion, int transportType, int port, int tls, SI_Socket ** cSocket, char * cip, uint16_t cport);

int __si_socket_engine__get_client_ip_port( SI_Socket * socket, char * str, int * port);

#endif






















