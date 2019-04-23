#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "osip_md5.h"
#include "algorithm.h"
#include <string.h>
#include <stdio.h>  
#include <stdlib.h>  
#include <time.h>
#include <eXosip2/eXosip.h>

#define SIPERROR -1
#define SIPSUCCESS 0
#define REQUEST 1
#define RESPONSE 0
#define PORT 7100
#define DEFAULT_IPC_SIPSVR_PORT 7100
#define VIDEOPORT    8402
#define REMOTESIP "sip:32010000001320000001@192.168.75.101:7100"
#define LOCALSIP "sip:32010000001120000001@192.168.75.109"
#define DEFAULT_LOCAL_SIP_USR   "34020000002000000002"
#define DEFAULT_LOCAL_SIP_PWD    "12345678" 
#define MAX_LEN         4096
#define MAX_IPC_NUM     256
#define MAX_STRING_LEN  256
#define DEVICE_LOST      1
#define DEVICE_ALIVE     0
#define DEFAULT_KEEP_ALIVE     3600
#define SAMPLE_INDEX             1
#define  min(a,b)  (((a) < (b)) ? (a) : (b))

class GBCallBack
{
public:
    
	virtual ~GBCallBack() {}
    
    /**
     *  for receiving video data
     *
     *  @param data Receives the video data
     *  @param timestamp The timestamp of received the video data
     *  @param memberID The id of audience
     *
     *  @return result (0:right, !0:fail)
     */
    virtual void OnRecVideoDataCallback(void *data, int bufsize, int data_len) = 0;
    
};
