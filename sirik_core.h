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

#ifndef SIRIK_CORE_H
#define SIRIK_CORE_H

#define IS_BIG_ENDIAN (!(union { uint16_t u16; unsigned char c; }){ .u16 = 1 }.c)

#define SI_STREAM_STRUCT_SIZE				1024
#define SI_STREAM_BUFFER_SIZE				2050
#define LOG_MEDIA_LOWER_LIMIT   1
#define LOG_MEDIA_FILE          1
#define LOG_MEDIA_CONSOLE       2
#define LOG_MEDIA_IDE           3
#define LOG_MEDIA_NEW_CONSOLE   4
#define LOG_MEDIA_UPPER_LIMIT   4

#define SI_LOG_LOWER_LIMIT   1
#define SI_LOG_CRITICAL      1
#define SI_LOG_ERROR         2
#define SI_LOG_WARNING       3
#define SI_LOG_INFO          4
#define SI_LOG_NORMAL        4
#define SI_LOG_DEBUG         5
#define SI_LOG_UPPER_LIMIT   5

#define SI_STK_LOG      	0
#define SI_PER_LOG      	1
#define SI_APP_LOG      	2
#define SI_BUF_LOG1      	3
#define SI_CMN_LOG      	3
#define SI_CUS_LOG2      	4
#define SI_CUS_LOG3      	5

#define LOGGER_ERR_LEVEL          1
#define LOGGER_ERR_MODE           2
#define LOGGER_ERR_FILE           3
#define LOGGER_ERR_NEW_CONSOLE    4
#define LOGGER_ERR_SEMAPHORE      5
#define LOGGER_ERR_BUFFER         6

#define LOGGER_WAIT_TIME        5000        
#define LOGGER_BUFFER_SIZE    	3000  
#define DATE_STRING_LEN         27
#define PATH_MAX_SIZE           260
#define MODULE_NAME_MAX_SIZE    50
#define LOG_MESSAGE_MAX_SIZE    LOGGER_BUFFER_SIZE - 100

#define LOG_CAT_CORE        					0	
#define LOG_CAT_STREAM							1
#define LOG_CAT_BUFFER							2
#define LOG_CAT_HTTP2							3 			
#define LOG_CAT_FG_INTERFACE					4   
#define LOG_CAT_APP								5

#define uint128_t __uint128_t

#define __si_aligned(a) __attribute__((__aligned__(a)))
#define __si_packed __attribute__((__packed__))
#define __si_weak __attribute__((__weak__))
#define __si_used __attribute__((used))
#define __si_unused __attribute__((__unused__))
#define SI_SET_USED(x) (void)(x)


//#define SCTP_PACKED __attribute__((packed))

//__si_log
// __attribute__((__packed__)) 

#pragma pack(4)
typedef struct __si_split_data
{
	char * src;
	int srclen;
	char tokens[10][20];
	int count;
} __si_split_data_t;

int __si_split( __si_split_data_t * sdata, char * splitter);

#pragma pack(4)
typedef struct __si_intLeaf
{
	struct __si_intLeaf * Nodes;
	int Value;
	uint8_t GenId;
	uint8_t * DataPtr;
} SI_IntLeaf;

#pragma pack(4)
typedef struct __si_intLeafRoot
{
	SI_IntLeaf * LeafRoot;
	pthread_mutex_t Lock;
} SI_IntLeafRoot;

#pragma pack(4)
typedef struct __si_LeafPath
{
	int leafValues[10];
	int iTotalLeafes;
	int IntValue;
} SI_LeafPath;

#pragma pack(4)
typedef struct __si_timer
{
	struct __si_timer * Next;
	uint32_t isReleased;
	uint32_t isCleared;	
	
	uint8_t * data;
	void ( * handler) ( uint8_t *);	
} SI_Timer;



typedef	void (*__si_addLL)( uint8_t * tree, uint8_t * item, uint32_t iVal);
typedef	void (*__si_findByIntLL)( uint8_t * tree, uint8_t ** item, uint32_t iVal);
typedef	void (*__si_findByIntAndRemoveLL)( uint8_t * tree, uint8_t ** item, uint32_t iVal);	

#pragma pack(4)
typedef struct __si_intLeafLL
{
	struct __si_intLeafLL * Nodes;
	pthread_mutex_t Lock;	
	uint8_t * Head;
	uint8_t * Current;
	uint32_t Count;
	uint16_t index;
	__si_addLL addFunc;
	__si_findByIntLL findByIntFunc;
	__si_findByIntAndRemoveLL findByIntAndRemoveFunc;
} SI_IntLeafLL;

void __si_initalize_LeafLL( SI_IntLeafLL * oIntLeafLL, __si_addLL _addFunc, __si_findByIntLL _findByIntFunc, __si_findByIntAndRemoveLL _findByIntAndRemoveFunc);
void __si_addItemToLeafLL( SI_IntLeafLL * oIntLeafLL, uint8_t * item, uint32_t iVal);
void __si_findByIntAndRemoveLeafLL( SI_IntLeafLL * oIntLeafLL, uint8_t ** item, uint32_t iVal);

#pragma pack(4)
typedef struct __si_thread
{
	struct __si_thread * Next;
	
	pthread_t id;

	long int LastTotalProcessedCount;
	int LastProcessedCount;
	
	long int TotalProcessedCount;
	long int TotalProcessedTime;
	int AvgProcessedTime;
	int MaxTimeTakenCounter;
	int isActive;
	long int LastTimerTick;
} SI_Thread;

#pragma pack(4)
typedef struct __si_queue
{
	struct __si_queue * Next;
	uint32_t isReleased;
	
	uint8_t * data;
	void ( * handler) ( uint8_t *);
} SI_Queue;

#pragma pack(4)
typedef struct __si_stream
{
	int len;								//first 3 bytes
	uint8_t Type;
	char Flags;
	uint32_t StreamId;						//last 4 bytes ( 1 + 31 bits);
	uint8_t EndStream;
	uint8_t iWeight;
	
	uint8_t isReleased;
	
	//char * buffer;
	//char buffer[SI_STREAM_STRUCT_SIZE];
	char buffer[SI_STREAM_BUFFER_SIZE];
	uint8_t * _conn;
	
	struct __si_stream * PoolNext;

	/* for ll in stream-buffer */
	struct __si_stream * StreamHead;
	struct __si_stream * StreamCurrent;
	/* for ll in stream-buffer */

	/* for ll in http-connection */
	struct __si_stream * Head;
	struct __si_stream * Current;
	/* for ll in http-connection */
} SI_Stream;


#pragma pack(4)
typedef struct __si_Task
{
	struct __si_Task * PoolNext;
	uint32_t isReleased;
	
	uint32_t Step;
	uint32_t Status;
	uint32_t Error;
	
	uint32_t TaskType;
	
	uint8_t * objData_1;	
	uint8_t * objData_2;
	uint8_t * objData_3;
	uint8_t * objData_4;
	int int1;
	uint64_t u64_1;
	uint64_t u32_1;
} SI_Task;

void __si_releaseTask( SI_Task * _task);
SI_Task * __si_allocateTask();

typedef void (*__si_event_callaback)( uint16_t eventType, uint8_t  * eventDataPtr);

#pragma pack(4)
typedef struct __si_execution_time
{
	struct timeval before;
	struct timeval after;
	struct timeval lapsed;
} SI_ExecTime; 

void __si_StartExecTime( SI_ExecTime * oExecTime);
void __si_EndExecTime( SI_ExecTime * oExecTime);

int __si_fileExists( char * fileName);
 
 
#pragma pack(4)
typedef struct __si_perfcounter
{
	struct __si_perfcounter * Next;
	
	char Name[100];
	
	uint64_t lastCount;
	uint64_t Count;
	
	uint64_t lastErrorCount;
	uint64_t Error;

	pthread_mutex_t lock;

	uint64_t lastProcessInZeroSeconds;
	uint64_t lastProcessInOneSecond;
	uint64_t lastProcessInTwoSeconds;
	uint64_t lastProcessInThreeSeconds;
	uint64_t lastProcessInFourSeconds;
	uint64_t lastProcessInFiveSeconds;
	uint64_t lastProcessInAboveFiveSeconds;
	
	uint64_t ProcessInZeroSeconds;
	uint64_t ProcessInOneSecond;
	uint64_t ProcessInTwoSeconds;
	uint64_t ProcessInThreeSeconds;
	uint64_t ProcessInFourSeconds;
	uint64_t ProcessInFiveSeconds;
	uint64_t ProcessInAboveFiveSeconds;
	
} __si_perfcounter_t;

void __si__perfcounter_init( __si_perfcounter_t * pCounter, char * name);
void __si__perfcounter_count( __si_perfcounter_t * pCounter, SI_ExecTime * execTime, int bError);
void __si__perfcounter_log( __si_perfcounter_t * pCounter);
void __si__per_log_pending_fsmqueuecount( char * name, void * queue);
void __si__per_log_pending_queuecount( char * name, void * queue);
int __si__queuecount( void * queue);

typedef	void (*__si_mpscounter)();
void __si_set_mpscounter( __si_mpscounter Handler);

uint16_t __si_http2_getInt16( char *cBuffer);

time_t * __si_core__get_start_time();
uint32_t __si_core__get_start_time_as_u32( uint32_t addseconds);
void __init_sirik_core();
int __si_ValidateMACAddress( char * macAddress);
void __si_createLicenseKey( char * macAddress);
void __si_retrieveLicenseKey( char * base64);

uint8_t * __si_malloc( size_t size);
void __si_malloc2( size_t size, uint8_t ** dataPtr);

void __si_malloc_register( size_t size);
uint8_t * __si_malloc_block( size_t size, char * file, int line);

int Base64encode(char *encoded, const char *string, int len);
int Base64decode(char *bufplain, const char *bufcoded);

void __si_TimeStameForFileName( char * datestring, int format);
void __si_makeDBTimeStamp( char * datestring);
void __si_makeTimeStamp( char * datestring);
void __si_makeTimeStamp2( struct timeval * tv, char * datestring, int convertToLocal);
void __si_print_timestamp_for_debug( char * prefix);

//void __si_malloc2( size_t size, uint8_t ** dataPtr);
void __si_initial_malloc();

void __si_decodeBitVal( uint8_t * bVal, char* _nwByte, int iFromIndex, int bitNumber);

void __si_encodeIntTo2Bytes( uint16_t * val, char * data);
void __si_encodeIntTo3Bytes( unsigned int * val, char * data);
void __si_encodeIntTo4Bytes( uint32_t * val, char * data);

uint16_t __si_getInt16( char *cBuffer);
uint16_t __si_get_u16( unsigned char * buff);
uint32_t __si_get_u24( unsigned char * buff);
uint32_t __si_get_u32( unsigned char * buff);
uint64_t __si_get_u40( unsigned char * buff);
uint64_t __si_get_u48( unsigned char * buff);
uint64_t __si_get_u64( unsigned char * buff);
void __si_decodeIntValueFrom3Bytes( unsigned int * iInt, char* nwByte, int iFromIndex);
void __si_decodeIntValueFrom4Bytes(unsigned int * iInt, char* _nwByte, int iFromIndex);

void __si_addStreamToStream( SI_Stream * _root_stream, SI_Stream * _stream);
uint32_t __si_copyStreamBuffer( SI_Stream * _stream, char * buffer);
uint32_t __si_getStreamLength( SI_Stream * _stream);

void __si_releaseStream( SI_Stream * _stream);
void __si_createStreamPool( int iSize, uint8_t bInLockMode);
SI_Stream * __si_allocateStream();

void __si_print_buffer( char * buff, int len);
void __si_print_buffer2( char *key, char * buff, int len, int haveSpace);
void __si_log_buffer( char * prefix, char * buff, int len);
void __si_print_string( char * buff, int len);
int __si_create_pthread2( void *(*start_routine) (void *), void *arg, char * funcName);
int __si_create_pthread_oncore( void *(*start_routine) (void *), void *arg, char * funcName, int cpu_id);

void __si_addBufferToStream( SI_Stream * _stream, char * buffer, int iLength);

void print_freeM_failed();

void __si_init_logger( char * rootPath);
void __si_init_logger2( char * rootPath);
void __si_configure_log( uint32_t mLogType,  uint32_t mLogLevel, char * logPrefix, char * logPath, int iPrintTimeStamp);
void __si_setall_log_prefix( char * logPrefix);
void __si_set_log_prefix( uint32_t mLogType, char * logPrefix);
void __si_set_log_level( uint32_t mLogType,  uint32_t mLogLevel);
void __si_log( uint32_t mLogType, uint32_t mLogCat, uint32_t mLogLevel, char* mLogMessage, ...);
void __si_log_cat_enable_all( uint32_t mLogType);
void __si_log_cat_disable_all( uint32_t mLogType);
void __si_log_cat_setName( uint32_t mLogType, uint32_t icat, char * catName);
int __si_getLocalTimeValue();
void __si_setLocalTimeValue( int ltv);
void __si_set_log_enable_disable( uint32_t mLogType,  int isEnabled);

uint8_t * __si_allocM( size_t size);
uint8_t * __si_allocM7( size_t size, const char * file, int line, uint16_t id);
uint8_t * __si_allocMV( size_t size);
void __si_allocMV2( size_t size, uint8_t ** dataPtr );
void * __si_allocMV1( size_t size);
void __si_freeM( uint8_t * ptr);
void __si_freeMV( void * ptr);

uint8_t * __si_allocR(  void * ptr, size_t size);
void __si_log_buffer_memory_stats();

SI_IntLeaf * __si_createRootIntLeaf();
void __si_allocateIntLeafNodes( SI_IntLeaf * intLeaf);
void __si_setLeafPath( SI_LeafPath * oLeafPath, int intVal);

void __si_setIntValueToIntLeafRoot( SI_IntLeafRoot * rootIntLeaf, int iIntValue, uint8_t * dataPtr);
void __si_getIntValueToIntLeafRoot( SI_IntLeafRoot * rootIntLeaf, int iIntValue, uint8_t ** dataPtr);

void __si_initalizeRootIntLeaf( SI_IntLeafRoot * intRootLeaf);

void __si_log_cat_enable_disable( uint32_t mLogType, uint32_t icat, int isEnabled);

void __si_core_set_max_fd( int iMaxFdCount);

typedef void (*eventHandlerFunc)( uint16_t , uint8_t *);

#pragma pack(4)
typedef struct __si_EventHandler
{
	uint16_t eventType; 
	eventHandlerFunc Handler;
} SI_EventHandler;


int __si_createDefaultEventSet1( int iNoOfProcess, __si_event_callaback e_call_back);
int __si_eventSetCreate1( uint8_t ** eventSetPtr, int iNoOfProcess, __si_event_callaback e_call_back);
void __si_addEvent1( uint8_t * eventSetPtr, uint16_t eventType, uint8_t  * eventDataPtr);

void __si_core_EventHandler1( uint16_t eventType, uint8_t  * eventDataPtr);
void __si_core_registerForEvent1( uint16_t eventType, eventHandlerFunc Handler);
//void __si_core_registerForEvent1( uint16_t eventType, void (*handler)( uint16_t , uint8_t *));

typedef void ( * app_event_handler)();
typedef void ( * queue_handler)( uint8_t *);
typedef void ( * timer_handler)( uint8_t *);

void __si_add_app_event_handler( app_event_handler handler);

void __si_core_queue( uint8_t * data, queue_handler handler);

// timeout
SI_Timer * __si_core_start_timer( uint8_t * data, timer_handler handler, int seconds);
void __si_core_clear_timer( SI_Timer * _timer);
void __si_initial_malloc_mb( int imb);
void __si_core_create_queue_processing_thread( int icount);
int  __si_TotalTimerPoolCount();
int  __si_AvailableTimerPoolCount();

void __si_core_set_queue_processing_thread_count( int icount);

void __si_printMallocStats();

int __si_core_get_last_processed_queue_count();
int __si_core_get_timer_tick();
long int __si_core_get_server_timer_tick();

/***********************************************/
#pragma pack(4)
typedef struct __si_counter
{
	struct __si_counter * Next;
	
	char Name[100];

	pthread_mutex_t Lock;	
	long int TotalProcessedCount;
	long int MaxLimit;
	long int CurrentCount;
	
	uint64_t lastRequest;	
	uint64_t Request;
	pthread_mutex_t RequestLock;
	
	uint64_t lastSendFailed;
	uint64_t SendFailed;
	pthread_mutex_t SendFailedLock;	
	
	uint64_t Response;
	pthread_mutex_t ResponseLock;
	
	uint64_t ErrorResponse;
	pthread_mutex_t ErrorResponseLock;	
	
	uint64_t Total;
	pthread_mutex_t TotalLock;	
} SI_Counter;

SI_Counter * __si_counter_create( long int liMaxLimit, char * name);
void __si_counter_init( SI_Counter * siCounter, long int liMaxLimit, char * name);
void __si_counter_reinit( SI_Counter * siCounter, int total);
int __si_counter_isMaxLimitReached( SI_Counter * siCounter);
int __si_counter_increment( SI_Counter * siCounter);
void __si_counter_decrement( SI_Counter * siCounter);
int __si_counter_increment_request( SI_Counter * siCounter);
int __si_counter_increment_send_failed( SI_Counter * siCounter);
int __si_counter_increment_request2( SI_Counter * siCounter, int cnt);
int __si_counter_increment_response( SI_Counter * siCounter);
int __si_counter_increment_error_response( SI_Counter * siCounter);
void __si_counter_plog( SI_Counter * siCounter);
void __si_counter_plog2( SI_Counter * siCounter);
void __si_counter_plog3( SI_Counter * siCounter);
void __si_counter_plog4( SI_Counter * siCounter, int logType);
void __si_counter_plog5( SI_Counter * siCounter);
/***********************************************/
// hash table

#pragma pack(4)
typedef struct __si_hashTableItem
{
	char * Key;
	uint8_t * DataPtr;
} SI_HashTableItem;

#pragma pack(4)
typedef struct __si_hashTable
{
	SI_HashTableItem ** Items;
	int KeySize;
	int TableSize;
	int Count;
	
	uint8_t usedMalloc;
	
	pthread_mutex_t Lock;
} SI_HashTable;

SI_HashTable * __si_createHashTable( int size, int keySize);
void __si_removeAllInHashTable( SI_HashTable * hTable);
void __si_deleteHashTable( SI_HashTable * hTable);

int __si_hashTable_free_rows_count( SI_HashTable * hTable);
long int __si_hashTable_add( SI_HashTable * hTable, char * key, uint8_t * dataPtr);
long int __si_hashTable_addlong( SI_HashTable * hTable, unsigned long key, uint8_t * dataPtr); 
void __si_hashTable_find( SI_HashTable * hTable, char * key, uint8_t ** dataPtr, uint8_t bDelete);
void __si_hashTable_findlong( SI_HashTable * hTable, unsigned long key, uint8_t ** dataPtr, uint8_t bDelete);

void __si_hashTable_delete( SI_HashTable * hTable, char * key);
// hash table
/***********************************************/
// power-table
#pragma pack(4)
typedef struct __si_powerTableItem
{
	struct __si_powerTableItem * PoolNext;	
	struct __si_powerTableItem * Next;
	struct __si_powerTableItem * PrevLevel;
	struct __si_powerTableItem * NextLevel;
	
	uint8_t Key;				//Item Key
	uint8_t * DataPtr;			//holds data and let user can differentiate this item
} SI_PowerTableItem;

#pragma pack(4)
typedef struct __si_powerTable
{
	SI_PowerTableItem * Root;
	SI_PowerTableItem * PoolHead;
	SI_PowerTableItem * PoolCurrent;
	
	int KeyElementsCount;					// holds total SI_PowerTableItem used count;
	int DataItemCount;						// holds total data elements
	int DeletedCount;
	
	pthread_mutex_t Lock;	
} SI_PowerTable;

SI_PowerTable * __si_power_table_create();
void __si_power_table_destroy( SI_PowerTable * pt);
void __si_power_table_rebuild( SI_PowerTable * pt);			//destroys Root and will create new Root
void __si_power_table_release_all( SI_PowerTable * pt);
void __si_power_table_swap( SI_PowerTable * pt, SI_PowerTable * ptNew);

int __si_power_table_get_item_count( SI_PowerTable * pt);

void __si_power_table_derive_key( SI_PowerTableItem * pti, char * key, int * len);

void __si_power_table_add( SI_PowerTable * pt, char * key, int keylen, uint8_t * dataPtr);
void __si_power_table_del( SI_PowerTable * pt, char * key, int keylen);
void __si_power_table_fnd( SI_PowerTable * pt, char * key, int keylen, uint8_t ** dataPtr);

void __si_power_table_add_lk( SI_PowerTable * pt, uint64_t key, uint8_t * dataPtr);
void __si_power_table_del_lk( SI_PowerTable * pt, uint64_t key);
void __si_power_table_fnd_lk( SI_PowerTable * pt, uint64_t key, uint8_t ** dataPtr);

void * __si_power_table_get_ptr_dataitem( void * pi_item_ptr);
void * __si_power_table_get_pending_ptr( SI_PowerTable * pt, void * lastPtr);

// power-table
/***********************************************/
// linked list

#pragma pack(4)
typedef struct __si_linked_list_item
{
	struct __si_linked_list_item * Next;
	struct __si_linked_list_item * Prev;	

	uint8_t * dataPtr;
}  SI_LinkedListItem; 

#pragma pack(4)
typedef struct __si_linked_list
{
	struct __si_linked_list * Next;
	
	SI_LinkedListItem * Head;
	SI_LinkedListItem * Current;
	
	int Count;
	int isReleased;
	
	pthread_mutex_t Lock;
} SI_LinkedList;

SI_LinkedList * __si_linked_list_allocate();
void __si_linked_list_release( SI_LinkedList *);

void __si_linked_list_add( SI_LinkedList *, uint8_t *);
int __si_linked_list_count( SI_LinkedList *);
void __si_linked_list_removeAll( SI_LinkedList *);
uint8_t * __si_linked_list_pop( SI_LinkedList * ll);
void __si_linked_list_push( SI_LinkedList * ll, uint8_t *);
uint8_t * __si_linked_list_get_item( SI_LinkedList * ll, int index);
int __si_linked_list_remove_itemAt( SI_LinkedList * ll , int index);
int __si_linked_list_remove_item( SI_LinkedList * ll , uint8_t * u8ItemToRemove);

SI_LinkedList * __si_readdir( char * dir);
// linked list


/***********************************************/
void __si_core_create_bulk_queue( void **queuePoolObject, int maxQueueItems);
int  __si_core_queue_bulk_items_force( void * queuePoolObject, uint8_t ** dataItem, int force, int count);
int __si_core_queue_bulk_items_recv( void * queuePoolObject, uint8_t ** dataItem, int size);

void __si_core_create_queue( void **queuePoolObject, void (*ptrCallBackHandler)(void*, int), int iNoOfThreads, int maxQueueItems);
void __si_core_queue_set_mps( void * queuePoolObject, int mps);
int  __si_core_queue_item( void * queuePoolObject, void * dataItem);
int  __si_core_queue_item_force( void * queuePoolObject, void * dataItem, int force);

void __si_core_create_fsmqueue( void ** fsmQueuePoolObject, void (*ptrCallBackHandler)(void*, int), int iNoOfThreads, int maxQueueItems);
int __si_core_queue_fsm( void * fsmQueuePoolObject, uint32_t index, void * dataItem);
int __si_core_queue_fsm2( void * fsmQueuePoolObject, uint32_t index, void * dataItem, void (*ptrCallBackHandler)(void *));

/***********************************************/
void __si_core_print_buffer( uint8_t * buffer, int len);

uint8_t __si_core_getU8RAND();
uint16_t __si_core_getU16RAND();
uint32_t __si_core_getU32RAND();
uint64_t __si_core_getU64RAND();

uint8_t __si_core_getU8RANDRange( uint8_t min, uint8_t max);
uint16_t __si_core_getU16RANDRange( uint16_t min, uint16_t max);
uint32_t __si_core_getU32RANDRange( uint32_t min, uint32_t max);
uint64_t __si_core_getU64RANDRange( uint64_t min, uint64_t max);

void __si_core_wait();
void __si_core_wait_secs( int secs);

int __si_convertStrToBCD( char * inStr, int inLen, char * outStr, int * outLen);
int __si_convertBCDToStr( char * inStr, int inLen, char * outStr, int * outLen);

int __si_convertBCDToBCDStr( char * inbcd, int inbcdlen, char * outbcdstr, int * outbcdstrlen);
int __si_convertBCDStrToBCD( char * inbcdstr, int inbcdstrlen, char * outbcd, int * outbcdlen);

int __si_convertStringToBCD( char * inStr, int inLen, char * outStr, int * outLen, uint8_t OddEvenIndication);
int __si_convertLongToBCD( uint64_t emergencyNumber, char * outStr, int * outLen, uint8_t OddEvenIndication);

int __si_convertApnToGtpApn( char * inStr, int inLen, char * outStr, int * outLen);
int __si_convertGtpApnToApn( char * inStr, int inLen, char * outStr, int * outLen);

void * __si_bcd_to_buffer(const char *in, void *out, int *out_len);
void * __si_bcd_to_buffer_reverse_order(const char *in, void *out, int *out_len);
void * __si_buffer_to_bcd(uint8_t *in, int in_len, void *out);

uint32_t __si_core_convert_ipv4toint( char * ipaddress);
char * __si_core_convert_inttoipv4( uint32_t ipv4);
void __si_core_convert_inttoipv4_2( uint32_t ipv4, char * ip);

void __si_core_fill_dummy_data( unsigned char * data, int len);
void __si_core_str_fill_rand_hex_string( unsigned char * data, int len);
int __si_conver_str_to_hex( char * hexout, char * hexstrin);			//hexstr to hex
int __si_conver_hex_to_hexstr( char * hexstrout, char * hexin, int inlen);

#pragma pack(4)
typedef struct __si_async_message
{
	uint8_t * data1;
	uint8_t * data2;
	uint8_t * data3;
	uint32_t timeOutValue;
	
} SI_AsyncMessage;

void __si_core_run_async( SI_AsyncMessage * asyncMsg);

#pragma pack(4)
typedef struct __si_u32
{
	uint32_t val;
	uint32_t isset;
} SI_U32;

#pragma pack(4)
typedef struct __si_u64
{
	uint64_t val;
	uint32_t isset;
} SI_U64;

#pragma pack(4)
typedef struct __si_i32
{
	int32_t val;
	uint32_t isset;
} SI_I32;

#pragma pack(4)
typedef struct __si_i64
{
	int64_t val;
	uint32_t isset;
} SI_I64;

#pragma pack(4)
typedef struct __si_stringv
{
	u_char * val;
	uint16_t len;
	uint16_t pos;
	uint16_t isset;	
	char vType;
} __si_stringv_t;

int __si_stringv_init( __si_stringv_t * str, int maxlen);
void __si_stringv_memset( __si_stringv_t * str);
void __si_stringv_append( __si_stringv_t * str, char * mLine, int len);
void __si_stringv_appendline( __si_stringv_t * str, char * mLine, ...);
void __si_stringv_printf( __si_stringv_t * str);

#pragma pack(4)
typedef struct __si_string5
{
	u_char val[6];
	uint16_t len;
	uint16_t isset;
} __si_string5_t;

#pragma pack(4)
typedef struct __si_string10
{
	u_char val[11];
	uint16_t len;
	uint16_t isset;
} __si_string10_t;

#pragma pack(4)
typedef struct __si_string20
{
	u_char val[21];
	uint16_t len;
	uint16_t isset;
} __si_string20_t;

#pragma pack(4)
typedef struct __si_string40
{
	u_char val[41];
	uint16_t len;
	uint16_t isset;
} __si_string40_t;

#pragma pack(4)
typedef struct __si_string60
{
	u_char val[61];
	uint16_t len;
	uint16_t isset;
} __si_string60_t;

#pragma pack(4)
typedef struct __si_string80
{
	u_char val[81];
	uint16_t len;
	uint16_t isset;
} __si_string80_t;

#pragma pack(4)
typedef struct __si_string100
{
	u_char val[101];
	uint16_t len;
	uint16_t isset;
} __si_string100_t;

#pragma pack(4)
typedef struct __si_string120
{
	u_char val[121];
	uint16_t len;
	uint16_t isset;
} __si_string120_t;

#pragma pack(4)
typedef struct __si_string140
{
	u_char val[141];
	uint16_t len;
	uint16_t isset;
} __si_string140_t;

#pragma pack(4)
typedef struct __si_string160
{
	u_char val[161];
	uint16_t len;
	uint16_t isset;
} __si_string160_t;

#pragma pack(4)
typedef struct __si_string180
{
	u_char val[181];
	uint16_t len;
	uint16_t isset;
} __si_string180_t;

#pragma pack(4)
typedef struct __si_string200
{
	u_char val[201];
	uint16_t len;
	uint16_t isset;
} __si_string200_t;


void __si_stringv_put( __si_stringv_t * ptr_string);
int __si_stringv_set( __si_stringv_t * ptr_string, u_char * val, uint16_t len);
int __si_stringv_setr( __si_stringv_t * ptr_string, u_char * val, uint16_t len);
int __si_string5_set( __si_string5_t * ptr_string, u_char * val, uint16_t len);
int __si_string10_set( __si_string10_t * ptr_string, u_char * val, uint16_t len);
int __si_string20_set( __si_string20_t * ptr_string, u_char * val, uint16_t len);
int __si_string40_set( __si_string40_t * ptr_string, u_char * val, uint16_t len);
int __si_string60_set( __si_string60_t * ptr_string, u_char * val, uint16_t len);
int __si_string80_set( __si_string80_t * ptr_string, u_char * val, uint16_t len);
int __si_string100_set( __si_string100_t * ptr_string, u_char * val, uint16_t len);
int __si_string120_set( __si_string120_t * ptr_string, u_char * val, uint16_t len);
int __si_string140_set( __si_string140_t * ptr_string, u_char * val, uint16_t len);
int __si_string160_set( __si_string160_t * ptr_string, u_char * val, uint16_t len);
int __si_string180_set( __si_string180_t * ptr_string, u_char * val, uint16_t len);
int __si_string200_set( __si_string200_t * ptr_string, u_char * val, uint16_t len);
int __si_u32_set( SI_U32 * u32, uint32_t val);
int __si_u64_set( SI_U64 * u64, uint64_t val);

#pragma pack(4)
typedef struct __si_imsi_range
{
	struct __si_imsi_range * Next;
	
	long imsiMin;
	long imsiMax;
} SI_IMSIRange;

#pragma pack(4)
typedef struct __si_imsi
{
	struct __si_imsi * Next;
	unsigned char IMSI[16];
} SI_Imsi;

#pragma pack(4)
typedef struct __si_diam_node
{
	struct __si_diam_node * Next;
	
	char Id[30];
	char sHostName[200];
	char sRealm[200];
	char sProductName[200];
	
	struct {
		uint32_t cmdCode[5];
		uint32_t cmdCodeCount;
	} cmdCodes;
	
	uint32_t VendorId;
	uint32_t OriginStateId;
	
	//uint32_t ApplicationId[5];
	//uint32_t ApplicationIdCount;

	uint32_t AuthApplicationId[5];
	uint32_t AuthApplicationIdCount;
	
	uint32_t VendorSpecificAuthApplicationId[5];
	uint32_t VendorSpecificAuthApplicationVendorId[5];	
	uint32_t VendorSpecificAuthApplicationIdCount;
	
	uint32_t AcctApplicationId[5];
	uint32_t AcctApplicationIdCount;

	uint32_t VendorSpecificAcctApplicationId[5];
	uint32_t VendorSpecificAcctApplicationVendorId[5];	
	uint32_t VendorSpecificAcctApplicationIdCount;
	
	SI_IMSIRange * ImsiRangeHead;
	SI_IMSIRange * ImsiRangeCurrent;
	uint32_t hasImsiRange;
	
	SI_Imsi * imsiListHead;
	SI_Imsi * imsiListCurrent;
	uint32_t hasImsiList;
	
	char sIP[5][40];							//Server IP's,, when opening connection 
	uint32_t sIPCount;
	uint32_t IPVersion;
	uint32_t IPTransportType;					// 1 - tcp, 2 - udp, 3 - sctp
	uint32_t IPPort;
	uint32_t IPCount;
	uint32_t isEnabled;
	
	char sHostIP[5][40];
	uint32_t sHostIPCount;	
	uint32_t CPort;								// CPort = when connecting to server connect on specific port
	uint32_t sHostIPVersion;
	
	struct __si_diam_node * hostNode;
	
	struct __si_diam_node * peerTablePrev;
	struct __si_diam_node * peerTableNext;
	void * ptrClientThread;
	
	uint64_t lastRequestNumber;
	uint64_t RequestNumber;
	uint64_t lastSentMessages;
	uint64_t SentMessages;	
	uint64_t lastSentMessagesFailed;
	uint64_t SentMessagesFailed;
	uint32_t IsDynamicAdded;
	uint32_t PeerInit;
	
	pthread_mutex_t RequestNumberLock;
	pthread_mutex_t SentMessagesLock;
	
	uint8_t  * vSiSocket;
	uint8_t  isCERSuccess;
	uint32_t CERCounter;
	uint8_t  isHost;
	uint64_t RoutedCount;
	uint32_t DWRTimer;
	uint32_t ReConnectSecs;
	//uint32_t PeerOrClient;	//satisfied with isHost	//1 - Peer (this node send request to server), 2 - Client, received new connection from client
	int IsApplicationServer;	// -1 Not Set, 0 Client, 1 - Server, 
	int DontConnect;
	
	uint16_t SCTP_MaxOStreams;
	uint16_t SCTP_MaxIStreams;
} SI_DiamNode;





#define SI_MAX_BUFFER_SIZE								4000
#define SI_MAX_BUFFER_ERROR_INSUFFICENT					501




#pragma pack(4)
typedef struct __si_buffer
{
	u_char buffer[SI_MAX_BUFFER_SIZE];
	uint32_t len;
	uint32_t pos;
	uint32_t Error;
} SI_Buffer; 

uint8_t __si_uint8_to_hex( uint8_t u8);
uint8_t __si_uint8_to_hex2( uint8_t u8);
uint8_t __si_uint8_to_hex2_with_swap( uint8_t u8);
uint8_t __si_nibble_swapu8( uint8_t u8);
uint8_t __si_nibble_swap( uint8_t u8);
uint8_t __si_nibble_high( uint8_t u8);
uint8_t __si_nibble_low( uint8_t u8);

uint8_t __si_buffer_get_u8( SI_Buffer * siBuffer);
uint16_t __si_buffer_get_u16( SI_Buffer * siBuffer);
uint32_t __si_buffer_get_u24( SI_Buffer * siBuffer);
uint32_t __si_buffer_get_u32( SI_Buffer * siBuffer);

#pragma pack(4)
typedef struct __si_keyvalpair
{
	struct __si_keyvalpair * Next;
	
	u_char * key;
	int keylen;
	u_char * val;
	int vallen;
} SI_KeyValPair;

int __si_indexOf( u_char * data, uint16_t datalen, uint8_t cchar);
int __si_lastIndexOf( u_char * data, uint16_t datalen, uint8_t cchar);
int __si_indexOf2( u_char * data, uint16_t datalen, u_char * str);
int __si_indexOf3( u_char * data, int datalen, u_char * find, int findlen);
int __si_indexOf4( u_char * data, u_char * find);
int __si_find_string( u_char * data, int datalen, u_char * find, int findlen);
char * __si_get_keypair_val( u_char * data, u_char * key);
SI_KeyValPair * __si_get_KeyValPair( u_char * data, int len, char * splitter);
void __si_fill_KeyValPair( u_char * data, int len, char * splitter, char * key, char * val);

SI_LinkedList * __si_getlines_n( u_char * data, int len);
SI_LinkedList * __si_getlines_rn( u_char * data, int len);
SI_LinkedList * __si_string_split( u_char * data, int len, char * cspliter);
SI_LinkedList * __si_string_double_split( u_char * data, int len, char * sp1it_1, char * split_2);

void __si_substr( u_char * data, u_char * outdata, int bPos, int ePos);
char * __si_ltrim( char * data);
char * __si_ltrim_copy( char * data, char * dst, int len);


void __si_hexString_to_hexArray( u_char * uIn, int len, u_char * uOut);
void __si_hexArray_to_hexString( u_char * uIn, int len, u_char * uOut);
u_char __si_hex2char( uint8_t hex );
uint8_t __si_char2hex( char c);

void __si_set_logger_rootpath( char * rootPath);

void __si_encode_uint64( uint8_t * data, uint64_t value);
void __si_encode_uint64_to5bytes( uint8_t * data, uint64_t value);
void __si_encode_uint32_to45bytes( uint8_t * data, uint32_t value);
void __si_encode_uint32_to4bytes( uint8_t * data, uint32_t value);
void __si_encode_uint32_to3bytes( uint8_t * data, uint32_t value);
void __si_encode_int32_to4bytes( uint8_t * data, int32_t value);
void __si_encode_uint16_to2bytes( uint8_t * data, uint16_t value);
void __si_encode_int16_to2bytes( uint8_t * data, int16_t value);

void __si_bit__U8_setbit( uint8_t * u8, uint8_t bitIndex);
void __si_bit__U16_setbit( uint16_t * u16, uint8_t bitIndex);
void __si_bit__U32_setbit( uint32_t * u32, uint8_t bitIndex);

uint8_t __si_bit__U8_isbitset( uint8_t u8, uint8_t bitIndex);
uint8_t __si_bit__U16_isbitset( uint16_t u16, uint8_t bitIndex);
uint8_t __si_bit__U32_isbitset( uint32_t u32, uint8_t bitIndex);


int __si_nanosleep( long tv_nsec /* 0 to 999999999*/ );

#pragma pack(4)
typedef struct __si_file_info
{
	int st_status;
	struct stat st;
	FILE * file;
	int pos;
} SI_FileInfo;

int __si_file__init( char * path, SI_FileInfo * fileInfo);
void __si_file__close( SI_FileInfo * fileInfo);
int __si_file__read( SI_FileInfo * fileInfo, u_char * buff, int readSize, int * pending);
int __si_file__hasdata( SI_FileInfo * fileInfo);
int __si_file__get_extension( u_char * filename, u_char * ext, int * extLen);

int __si_file__readdata( char * fileName, int pos, u_char * buff, int readSize);

typedef struct __si_core_queue SI_CoreQueue;

SI_CoreQueue * __si_core_create_queueobject( int forAppWorkerThreads, int maxQueueItems);
int __si_core_queue_wait( SI_CoreQueue * objQueue, uint8_t ** dataItem);
int __si_core_queue_post( SI_CoreQueue * objQueue, uint8_t * item);

int __si_file__createf( char * cFileName, uint8_t deleteExisting);
void __si_file__write( int fhd, char * contents);
void __si_file__writeln( int fhd, char * contents, ...);
void __si_file__writef( int fhd, char * contents, int len);
void __si_file__closef( int fhd);
int __si_file__writeallf( char * cFileName, uint8_t deleteExisting, char * contents, int len);

void __si_makeIntFileName( char *mFileNameBuffer, char * mPath, char * mFilePrefix, int * iFileIndex);
void __si_makeDateTimeFileName( char * mFileNameBuffer, char * mPath, char * mFilePrefix, char * ext);
void __si_makeFileName( char * mFileNameBuffer, char * mPath, char * mFileName, uint64_t numb, char * ext);
uint64_t __si_uniqueno( uint64_t yeild);


void ngtff__u32id_to_charid( uint32_t uid, char * cid);
void ngtff__charid_to_u32id( char * cid, uint32_t * uid);

uint8_t * ngtff_itable__create( uint32_t count, uint32_t ssize);
uint8_t * ngtff_itable__getfree_item( uint8_t * itable);
void ngtff_itable__putitem( uint8_t * itable, uint8_t * row);
uint32_t ngtff_itable__getitem_id( uint8_t * row);
uint8_t * ngtff_itable__getitem_bufferpointer( uint8_t * row);
uint8_t * ngtff_itable__getitem_byid( uint8_t * itable, uint32_t id);

#pragma pack(4)
typedef struct __ng_fsm
{
	struct __ng_fsm * Next;
	
	int action;
	uint8_t * executor;
} NG_FSM;

typedef struct __ng_fsm_thread __ng_fsm_thread_t;

#define NGTFF__FSM__NEXT							100
#define NGTFF__FSM__STOP							200

#pragma pack(4)
typedef struct __ng_fsm_q
{
	uint8_t * object;
	uint32_t status;
	//uint32_t isInQ;
	//pthread_mutex_t isInQLock;
	
	NG_FSM * Head;
	NG_FSM * Current;
	pthread_mutex_t Lock;
	
	__ng_fsm_thread_t * fThread;
} NG_FSMQ;


#pragma pack(4)
typedef struct __ng_fsm_thread
{
	void * msgQueue;
	int (*ptrCallBackHandler)( NG_FSMQ *, int);
} __ng_fsm_thread_t;

void ngtff_fsmq_init( NG_FSMQ * fsmq, uint8_t * object, __ng_fsm_thread_t * fThread);
__ng_fsm_thread_t * ngtff_fsmq_create_thread( int (*ptrCallBackHandler)( NG_FSMQ *, int), int iNoOfThreads);
void  ngtff_fsmq_addaction( NG_FSMQ * fsmq, int action, uint8_t * executor);


/*
	Request-ID
	SessionStateId
	timer
	Interface-ID / Tagrget NF-ID
	API-ID		/ API Call to which we sent request
	SessionObject
	Sub-Session
	Requesting NodeType ( -1 Common, 0 GRAN, 1 ERAN, 2 IWF)
	TransportObject
	Response-Data
	Response-Data-Length
*/

typedef struct __si_service_request SI_ServiceRequest;
typedef int (*si_ServiceRequestTimeoutHandler)( SI_ServiceRequest *);
typedef int (*si_ServiceRequestResponseHandler)( SI_ServiceRequest *);
typedef void (*si_ServiceRequestOnHttpResponse)( SI_ServiceRequest *, uint8_t * http2TransportObject);
typedef void (*si_ServiceRequestOnInterfaceSelection)( SI_ServiceRequest *, uint8_t * interfaceInfo);

#pragma pack(4)
typedef struct __si_service_request_data_item
{
	struct __si_service_request_data_item * Next;
	
	u_char key[100];
	uint32_t ParameterType;			// query string, path-parameter, object,
	uint32_t DataType;
	uint64_t IntVal;
	uint8_t * Data;
	
} SI_ServiceRequestDataItem;


#define SER_REQ_ROUTEON___RI						1
#define SER_REQ_ROUTEON___MCC_MNC					2
#define SER_REQ_ROUTEON___GROUPID					3
#define SER_REQ_ROUTEON___NSSAI						4
#define SER_REQ_ROUTEON___SUPI						5
#define SER_REQ_ROUTEON___NFID						6
#define SER_REQ_ROUTEON___URL						7

#pragma pack(4)
typedef struct __si_service_request
{
	struct __si_service_request * Next;
	
	uint32_t ServiceRequestId;
	
	// Through ApiId + InterfaceId, it will reach its dest function to exec 
	uint32_t ApiId;								//AV-REQ 
	uint32_t InterfaceId;						//NGAP, AMF, AUSF, SMF, SMSF
	SI_Timer * Timer;
	uint32_t TimeOutSeconds;
	uint8_t * transportObject;
	uint8_t transportObjectRetain;
	SI_ExecTime execTime;
	
	uint8_t * Object;					//SessionObject
	uint8_t * Data;
	uint8_t * ResponseData;
	char * ResponseContentType;
	uint8_t * userData;
	uint32_t userData_u32;
	uint32_t ResponseDataLength;
	int32_t ErrorCode;
	uint32_t RetryCount;
	
	u_char * location;

	uint16_t RouteOn;
	
	union 
	{
		uint16_t RoutindIndicator;
		u_char GroupId[32];
		uint64_t lsupi;
		struct 
		{
			u_char mcc[4];
			u_char mnc[4];
		} plmnId;
		struct 
		{
			uint8_t SST;
			u_char SD[4];
			uint8_t SD_isset;
		} Nssai[16];
		u_char nfId[50];
	} Route;
	uint16_t NssaiCount;
	
	char logtag[20];
	char serviceName[30];
	
	SI_ServiceRequestDataItem * DataItemHead;
	SI_ServiceRequestDataItem * DataItemCurrent;
	
	si_ServiceRequestTimeoutHandler onTimeOut;
	si_ServiceRequestResponseHandler onResponse;
	si_ServiceRequestOnHttpResponse onHttp2Response;
	
	uint8_t * selInterface;
	si_ServiceRequestOnInterfaceSelection OnIfSelection;
} SI_ServiceRequest;


SI_ServiceRequest * __si_ServiceRequest__allocate();
SI_ServiceRequest * __si_ServiceRequest__allocate2( uint32_t InterfaceId, uint32_t ApiId, uint32_t requestDataObjectSize);
void __si_ServiceRequest__release( SI_ServiceRequest * );
void __si_ServiceRequest__create( int size, int lockMode);

typedef int (*ServiceExecutionFunction)( SI_ServiceRequest *);

#pragma pack(4)
typedef struct __si_service_request_api
{
	struct __si_service_request_api * Next;
	
	uint32_t ApiId;
	ServiceExecutionFunction Func;
	
} SI_ServiceRequestAPI;

#pragma pack(4)
typedef struct __si_service_request_interfaec
{
	struct __si_service_request_interfaec * Next;
	uint32_t InterfaceId;
	SI_ServiceRequestAPI * apiHead;
	SI_ServiceRequestAPI * apiCurrent;
	
} SI_ServiceRequestInterface;

#pragma pack(4)
typedef struct __si_service_request_manager
{
	SI_ServiceRequestInterface * sriHead;
	SI_ServiceRequestInterface * sriCurrent;
	
} SI_ServiceRequestManager;

SI_ServiceRequestManager * __si_ServiceRequestManager__create();
int __si_ServiceRequestManager__register( SI_ServiceRequestManager *, uint32_t interfaceId, uint32_t apiId, ServiceExecutionFunction func);
int __si_ServiceRequestManager__execute( SI_ServiceRequestManager * srm, SI_ServiceRequest * serviceRequest);
int __si_ServiceRequestManager__executeAsync( SI_ServiceRequestManager * srm, SI_ServiceRequest * serviceRequest);

#pragma pack(4)
typedef struct __si_activity
{
	struct __si_activity * Next;
	
	uint8_t * Parent;
	uint16_t ParentType;
	
	uint32_t GroupId;
	uint32_t ActivityType;
	uint32_t ActivityFlow;		//Registration Flow, Service Request Flow
	queue_handler executor;
	uint16_t ActivityStage;
	uint16_t ActivityStatus;
	uint16_t ActivityStateId;
	uint16_t OnError;				//1-MOVE-NEXT, 2 - STOP PROCESSING, 3 CLOSE - SESSION
	
	uint8_t * data;
	
} SI_Activity;


SI_Activity * __si_Activity__allocate();
void __si_Activity__release( SI_Activity * );
void __si_Activity__create( int size, int lockMode);
int  __si_Activity__get_total_count();
int  __si_Activity__get_available_count();


u_char * __si_strdup( u_char * );
u_char * __si_strdup2( u_char * , int len);
u_char * __si_strdup3( u_char * , int startPos, int len);
u_char * __si_pstrdup( u_char *);

#pragma pack(4)
typedef struct __si_id_provider
{
	uint32_t BaseNo;
	uint32_t MaximumNo;		//	how to how much
	uint32_t Count;			// how many id reguired
} SI_IdProvider;

SI_IdProvider * __si_idProvider_create( uint32_t basNo, uint32_t MaximumNo, uint32_t Count);

uint32_t __si_idProvider_getNext( SI_IdProvider * idProvider, uint32_t uRotatedVal);
uint32_t __si_idProvider_calcBaseNo( SI_IdProvider * idProvider, uint32_t uIdNo);
uint32_t __si_idProvider_getBaseNo( SI_IdProvider * idProvider, uint32_t uRotatedVal);			//gets base (start no)	
uint32_t __si_idProvider_getIdNo( SI_IdProvider * idProvider, uint32_t uIdNo);					//gets 0 based index

typedef struct __si_index_table SI_IndexTable;

#pragma pack(4)
typedef struct __si_index_row
{
	struct __si_index_row * Next;
	
	uint32_t id;
	uint32_t next_id;
	SI_IndexTable * Parent;
	uint8_t * Object;
	uint8_t * Object2;
	SI_Timer * timer;
	timer_handler handler;
} SI_IndexRow;

uint32_t __si_indexRow_getId( SI_IndexRow *);
uint8_t * __si_indexRow_getObject( SI_IndexRow *);
uint8_t * __si_indexRow_getObject2( SI_IndexRow *);
void __si_indexRow_setObject(SI_IndexRow *, uint8_t *);
void __si_indexRow_setObject2(SI_IndexRow * iRow, uint8_t *);
void __si_indexRow_setTimerHandler(SI_IndexRow * iRow, timer_handler handler);
timer_handler __si_indexRow_getTimerHandler(SI_IndexRow * iRow);
void __si_indexRow_setTimer( SI_IndexRow * iRow, timer_handler handler, int seconds);
void __si_indexRow_clearTimer( SI_IndexRow * iRow);

#pragma pack(4)
typedef struct __si_index_table
{
	SI_IdProvider * idProvider;
	SI_IndexRow ** table;
	
	SI_IndexRow * rowHead;
	SI_IndexRow * rowCurrent;
	pthread_mutex_t Lock;
	
	uint32_t Total;
	uint32_t Available;
	uint64_t Used;
} SI_IndexTable;

SI_IndexTable * __si_IndexTable_create(  uint32_t baseId, uint32_t count);
SI_IndexTable * __si_IndexTable_create2( uint32_t baseId, uint32_t count, uint32_t max);
SI_IndexRow * __si_IndexTable_FindRow( SI_IndexTable * indexTable, uint32_t id);
SI_IndexRow * __si_IndexTable_getRow( SI_IndexTable *);
void __si_IndexTable_putRow( SI_IndexRow *);
void __si_IndexTable_plog( char * name, SI_IndexTable * indexTable);

void __si_generate_uuid4( char * dst);	//36 + 1 length

int __si__copy( const char * src, char * dst, int dst_str_len);

void __si_strcpy( char * dest, char * src);
void __si_strncpy( char * dest, char * src, int len);

int __si_memcmp( char * src1, char * src2, int len);
int __si_memcmp2( char * str1, uint16_t str1_len, char * str2, uint16_t str2_len);

int __si_convertLongToBCD2( uint64_t emergencyNumber, char * outStr, int * outLen);
int __si_convertStringToBCD2( char * inStr, int inLen, char * outStr, int * outLen);

void __si_ServiceRequest__setLogTag_u64( SI_ServiceRequest * serviceRequest, uint64_t uval);
void __si_ServiceRequest__setLogTag( SI_ServiceRequest * serviceRequest, char * str);

#pragma pack(4)
typedef struct __si_core_data_record
{
	uint8_t * data1;
	uint8_t * data2;
	uint8_t * data3;
	uint8_t * data4;
	
	/*
	long L1;
	long L2;
	*/
	
	struct __si_core_data_record * Next;
} SI_CoreDataRecord;


SI_CoreDataRecord * __si_core_allocate_data_record();
void __si_core_release_data_record( SI_CoreDataRecord * qRecord);

void * __si_hex_to_ascii( void *in, int in_len, void *out, int out_len);
void * __si_ascii_to_hex( char *in, int in_len, void *out, int out_len);

uint8_t * __si_strToPointer( u_char *);

void __si_enable_coredump();

int __si_dateInRange( char * cStartDate, char * cEndDate);



// dynamic pool
typedef struct __si_sirik_pool si_sirik_pool_t;

#pragma pack(4)
typedef struct __si_sirik_pool_item
{
	struct __si_sirik_pool_item * Next;
	si_sirik_pool_t * parent;
	uint32_t index;
	uint32_t isReleased;
} si_sirik_pool_item_t;

#pragma pack(4)
typedef struct __si_sirik_pool
{
	si_sirik_pool_item_t * Head;
	si_sirik_pool_item_t * Current;
	si_sirik_pool_item_t **indexDB;
	
	char name[100];
	uint32_t Available;
	uint32_t Total;
	uint32_t Extend;
	uint32_t Sz;
	uint64_t Used;
	pthread_mutex_t mLock;
} si_sirik_pool_t;

si_sirik_pool_t * __si_pool_create( char * name, size_t objSize, uint32_t count, uint32_t extend);
int __si_pool_create_index( si_sirik_pool_t * pool);
uint8_t * __si_pool_allocate( si_sirik_pool_t * pool);
void __si_pool_release( uint8_t * item);
uint8_t * __si_pool__find( si_sirik_pool_t * pool, uint32_t index);
uint32_t __si_pool_index( uint8_t * item);
uint32_t __si_pool_fsm_index( uint8_t * item, uint32_t fsmTCount);
void __si_pool_plog( si_sirik_pool_t * siPool);

// dynamic buffer
#pragma pack(4)
typedef struct __si_buf
{
	uint8_t * head;
	uint8_t * data;
	
	uint32_t at;	
	uint32_t len;
	uint32_t pos;
} __si_buff_t;

void __si_buff__init();
__si_buff_t * __si_buff__alloc( int msize);
__si_buff_t * __si_buff__alloc2( u_char * data, uint32_t len);
uint8_t * __si_buff__get_datapointer( __si_buff_t * buff);
uint8_t * __si_buff__get_current_datapointer( __si_buff_t * buff);
void __si_buff__free( __si_buff_t * si_buff);
void __si_buff__copy( __si_buff_t * si_buff, char * buff, int len);
uint16_t __si_buff__get_len( __si_buff_t * buff);
uint8_t * __si_buff__get_head( __si_buff_t * buff);

void __si_buff__reserve( __si_buff_t * si_buff, int pos);
void __si_buff__pull( __si_buff_t * si_buff, int pos, int setlength);

int __si_buff__enc_uint64( __si_buff_t * si_buff, uint64_t val);
int __si_buff__enc_uint32( __si_buff_t * si_buff, uint32_t val);
int __si_buff__enc_uint16( __si_buff_t * si_buff, uint16_t val);
int __si_buff__enc_uint8( __si_buff_t * si_buff, uint8_t val);

int __si_buff__enc_at_uint64( int pos, __si_buff_t * si_buff, uint64_t val);
int __si_buff__enc_at_uint32( int pos, __si_buff_t * si_buff, uint32_t val);
int __si_buff__enc_at_uint16( int pos, __si_buff_t * si_buff, uint16_t val);
int __si_buff__enc_at_uint8( int pos, __si_buff_t * si_buff, uint8_t val);


int __si_buff__dec_uint8( __si_buff_t * si_buff, uint8_t * val);
int __si_buff__dec_uint16( __si_buff_t * si_buff, uint16_t * val);
int __si_buff__dec_uint32( __si_buff_t * si_buff, uint32_t * val);
int __si_buff__dec_uint64( __si_buff_t * si_buff, uint64_t * val);

int __si_memcpy( char * dst, uint16_t dlen, char * src, uint16_t slen);
int __si_mkpath( const char * path, mode_t mode);

typedef struct __si_loadtestitem __si_loadtestitem_t;
typedef struct __si_loadtestinfo __si_loadtestinfo_t;
typedef struct __si_test_config __si_test_config_t;


typedef void (*fp_loadtest_executor)( uint64_t msgId, uint64_t totMsgId, __si_loadtestitem_t * testItem);
typedef void (*fp_loadtest_ontestcase)( __si_loadtestinfo_t * loadtestinfo, __si_test_config_t * testConfig);

#pragma pack(4)
typedef struct __si_test_config
{
	struct __si_test_config * Next;
	__si_loadtestinfo_t * Parent;
	
	fp_loadtest_executor executor; 
	uint32_t ApplicationId;				//DiamApplicationId, example hss -> 16777251
	char APIName[100];
	int APIId;
	int Enabled;
	char Info[500];
	int TPS;
	int Concurrent;
	int TotalCount;
	int RequestCount;
	pthread_mutex_t RequestCountLock;
	int ResponseCount;
	pthread_mutex_t ResponseCountLock;
	int Delay;
	uint32_t SleepTime;					//MILLI|MICRO|NANO 
	uint32_t StartFromBegining;
	uint32_t Repeat;
	//uint32_t RepeatCounter;
	
	// To Hold User Additional Data, Create json Object and add data
	uint8_t * jsonObject;
	
} __si_test_config_t;

#pragma pack(4)
typedef struct __si_loadtestitem
{
	__si_loadtestinfo_t * Parent;
	
	int index;
	uint32_t ReqNo; 
	uint8_t * context;
	__si_test_config_t * testConfig;

	
} __si_loadtestitem_t;

#pragma pack(4)
typedef struct __si_loadtestinfo
{
	sem_t sem_lock;
	int CallSemPost;
	pthread_mutex_t contextLock;
	int RequestCount;
	pthread_mutex_t RequestCountLock;
	int ResponseCount;
	pthread_mutex_t ResponseCountLock;
	pthread_mutex_t CallSemPostLock;


	uint32_t RequestPerSecond;
	uint64_t MaxMessagesPerThread;
	uint32_t SleepTime;					//MILLI|MICRO|NANO 
	fp_loadtest_executor executor; 
	fp_loadtest_ontestcase ontestcasebegin;
	__si_loadtestitem_t ** items;
	uint8_t * context;
	int Delay;
	int Concurrent;
	int TPS;
	int TestCaseExecutionType;				//1-Sequential, 2- Parrellel
	__si_test_config_t ** testConfig;		//configration of test case and scanarios
	int testConfigCount;
	si_sirik_pool_t * testItemPool;			//__si_loadtestitem_t
	void * queue;
} __si_loadtestinfo_t;

uint8_t * __si_loadtest__getFuncTestData( __si_loadtestitem_t * testItem);
__si_loadtestinfo_t * __si_loadtest_create( int noOfThreads, fp_loadtest_executor executor, uint32_t RequestPerSecond, uint64_t MaxMessagesPerThread, uint32_t SleepTime, uint8_t * context);

int __si_loadtest_create2( int noOfThreads, __si_loadtestinfo_t * loadtestinfo);
void __si_loadtest_response_recived( __si_loadtestitem_t * testItem);

void __si_str_to_plmn( char * strPlmn, char * plmn );
int __si_ip_get_version( char * ipAddr );
int __si_ValidateLocalIPv4( uint32_t ipv4);

uint32_t __si_hash_string__dhb2( uint8_t * str);
uint32_t __si_hash_string__fnv( uint8_t * str, int len);
uint32_t __si_hash_string__murmur32( uint8_t * str);
uint64_t __si_hash_string__murmur64( uint8_t * str);
uint32_t __si_hash_string__krv2( uint8_t * str);
uint32_t __si_hash_string__jenkins( uint8_t * str, int len);
uint32_t __si_hash_string__crc32b( uint8_t * str);
uint32_t __si__rotl32( uint32_t x, int32_t bits);
uint32_t __si_hash_string__coffin( uint8_t *input);
uint32_t __si_hash_string__x17( uint8_t * key, int len);


#define SI_LINEAR_HASH_TABLE_TYPE__UINT32			1
#define SI_LINEAR_HASH_TABLE_TYPE__UINT64			2
#define SI_LINEAR_HASH_TABLE_TYPE__INT32			3
#define SI_LINEAR_HASH_TABLE_TYPE__INT64			4
#define SI_LINEAR_HASH_TABLE_TYPE__STRING			5

#pragma pack(4)
typedef struct __si_linear_hash_col
{
	struct __si_linear_hash_col * Prev;
	struct __si_linear_hash_col * Next;
	uint8_t * key;
	uint8_t keylen;
	uint8_t * val;
} __si_linear_hash_col_t;

#pragma pack(4)
typedef struct __si_linear_hash_row
{
	__si_linear_hash_col_t * Head;
	__si_linear_hash_col_t * Current;
	uint32_t Count;
	pthread_mutex_t Lock;
} __si_linear_hash_row_t;

#pragma pack(4)
typedef struct __si_linear_hash_table
{
	uint8_t Type;
	uint8_t KeyLen;
	uint8_t HashFunc;
	uint8_t Spare;
	uint32_t ToalRowCount;
	uint32_t UsedRowCount;
	pthread_mutex_t Lock;
	__si_linear_hash_row_t ** table;
} __si_linear_hash_table_t;

__si_linear_hash_table_t * __si_linear_hash_table__create( uint8_t Type, uint8_t KeyLen, uint32_t capacity);
uint8_t __si_linear_hash_table__add_int32( __si_linear_hash_table_t * table, int32_t key, void * data);
uint8_t __si_linear_hash_table__add_uint32( __si_linear_hash_table_t * table, uint32_t key, void * data);
uint8_t __si_linear_hash_table__add_int64( __si_linear_hash_table_t * table, int64_t key, void * data);
uint8_t __si_linear_hash_table__add_uint64( __si_linear_hash_table_t * table, uint64_t key, void * data);
uint8_t __si_linear_hash_table__add_string( __si_linear_hash_table_t * table, char * key, int keylen, void * data);
uint8_t __si_linear_hash_table__del_int32( __si_linear_hash_table_t * table, int32_t key);
uint8_t __si_linear_hash_table__del_uint32( __si_linear_hash_table_t * table, uint32_t key);
uint8_t __si_linear_hash_table__del_int64( __si_linear_hash_table_t * table, int64_t key);
uint8_t __si_linear_hash_table__del_uint64( __si_linear_hash_table_t * table, uint64_t key);
uint8_t __si_linear_hash_table__del_string( __si_linear_hash_table_t * table, char * key, int keylen);
uint8_t __si_linear_hash_table__fnd_int32( __si_linear_hash_table_t * table, int32_t key, void ** data);
uint8_t __si_linear_hash_table__fnd_uint32( __si_linear_hash_table_t * table, uint32_t key, void ** data);
uint8_t __si_linear_hash_table__fnd_int64( __si_linear_hash_table_t * table, int64_t key, void ** data);
uint8_t __si_linear_hash_table__fnd_uint64( __si_linear_hash_table_t * table, uint64_t key, void ** data);
uint8_t __si_linear_hash_table__fnd_string( __si_linear_hash_table_t * table, char * key, int keylen, void ** data);

void 	__si_core_enable_perf_log();
void 	__si_CoreDumpOnMemoryRequest();
int 	__si_CoreDumpOnMemoryRequest_isEnabled();
void 	__si_LogMallocBlock();


#endif
















