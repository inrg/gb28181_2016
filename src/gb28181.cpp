
#include "gb28181.h"

/* 新增线程池相关函数 */
//#include <pthread>
#define HKREMOTESIP "sip:32010601562000000000@218.94.1.147:7100"

using namespace std;
//static int g_loop = 0;

static int g_video_port = 8402;


static int g_thread_index = 0;

//static int data_len = 0;
osip_body_t* invie_req_body;


class SIP_BASIC 
{	
	public :
		int  PrintMsg(int ch);
		void Remove_c(char *str);
		int  get_str( const char* data, const char* s_mark, bool with_s_make, const char* e_mark, bool with_e_make, char* dest );
		void  Answer200();
		void  Answer180( );
		void Set_je(eXosip_event_t * je);
		virtual ~SIP_BASIC();
		eXosip_event_t * m_je;
};


class SIP_IPC: public SIP_BASIC
{  
	public:  
		
		void SetSn(char* Sn);
		void SetUsr(char* usr);
		void SetPwd(char* pwd);

		void SetIp(char* ip);

		void SetSipPort(int sip_port);

		void BuildRemoteSipSvr();

		char * GetRemoteSipSvr();

		char * GetSN();
		char * GetIP();
		char * GetUsr();
		char * GetPwd();
		void SetVideoPort(unsigned int port);
		int GetVideoPort();

		void SetKeepAlive(int keep_alive);
		int GetKeepAlive();

		
		int DecreaseKeepAlive();
		void UpdateKeepAlive();
		void SetExpire(int expire);
		int GetExpire();
		//void  Set_invite_je(eXosip_event_t * je);
		void ClearDeviceData();
		
		SIP_IPC(void)
		{		
			m_videoport =  VIDEOPORT;
			memset(m_usr, 0, sizeof(m_usr));
			memset(m_pwd, 0, sizeof(m_pwd));
			memset(m_sn, 0, sizeof(m_sn));
			memset(m_ip, 0, sizeof(m_ip));
			memset(m_remotesip_srv, 0, sizeof(m_remotesip_srv));
			m_keepalive = 0;
			m_sipport = DEFAULT_IPC_SIPSVR_PORT;
			m_expire = 0;
		}
	private:   
		int   m_videoport; 
		char  m_usr[128];
		char  m_pwd[128];
		char  m_sn[128];
		int   m_keepalive;
		int   m_expire;
		char  m_ip[128];
		int   m_sipport;
		char  m_remotesip_srv[128];
		
};  

/* server 中 需要实现对应的回调函数 */

class SIP_SERVER:public SIP_BASIC, public GBCallBack
{
	public :
		void PushDeviceCatalog(char* rsp_xml_body);
		void Register();
		int RegisterAction(osip_message_t *reg);
		int RegisterHeart(eXosip_event_t* je, int expires, osip_message_t* reg, char *strAuth );
		int RegisterWithAuthentication(osip_message_t* reg, eXosip_event_t* je );
		int eXosipInitialize();
		void setserverport(int port);
		int getserverport();
		void ProcessRTPDataToPS(int * p_port);
		void GenerateRadom();
		char * GetNonce();
		int	Init_Server();
		void ResponseDeviceInfo(char* rsp_xml_body);
		int  ProcessRegister();	
		void ResponseDeviceStatus(char* rsp_xml_body);
		int  ProcessInvite();
		void ResponseDeviceBoot(char* rsp_xml_body);
		void ResponseCatalog(char* rsp_xml_body);
		void ProcessKeepAlive();
		void SendKeepAlive();
		void VideoFileQuery(char* rsp_xml_body);
		void Catalog(char* rsp_xml_body);
		void PTZ_Control_left(char* rsp_xml_body);
		int Call_Build_Initial_Invite(int index,const char * rtp_svr, int rtp_svr_port);
		int Get_Ipc_Num();
		void UpdateKeepAliveByDeviceID(char *device_id);
		void DeviceManage();
		void RemoveDevice(int index);
		int GetIpcVideoPortByIndex(int n);
		int Search_Device_ByIP(char * p_ip);
		void  OnRecVideoDataCallback(void * data, int buf_len , int  data_len);
		/* 设备注册时 需要对应的deviceID 均匹配 */
		int	Is_device_Register(char * DeviceID);
		void GetLocalIP();
		
		SIP_SERVER(void)
		{
			m_port = PORT;
			m_ipc_num = 0;
			memset(m_localsip, 0, sizeof(m_localsip));
			
			memset(m_remotesip, 0,sizeof(m_remotesip));

			memcpy(m_localsip, LOCALSIP, strlen(LOCALSIP));
			memcpy(m_remotesip, REMOTESIP, strlen(REMOTESIP)); 
			memcpy(m_serverusr, DEFAULT_LOCAL_SIP_USR, min(sizeof(m_serverusr), strlen(DEFAULT_LOCAL_SIP_USR)));
			
			memcpy(m_serverpwd, DEFAULT_LOCAL_SIP_PWD, min(sizeof(m_serverpwd), strlen(DEFAULT_LOCAL_SIP_PWD)));
			
			for(int loop = 0; loop < MAX_IPC_NUM; loop++)
			{
				ipc_list[loop] = NULL;
			}
			this->GenerateRadom();
			this->GetLocalIP();

		} 
		 ~SIP_SERVER();
	private :
		int m_port;
		char m_serverusr[MAX_STRING_LEN];
		char m_serverpwd[MAX_STRING_LEN];
		char m_remotesip[MAX_STRING_LEN];
		char m_localsip[MAX_STRING_LEN];
		char m_ip[MAX_STRING_LEN];
		char m_Nonce[32];
		SIP_IPC * ipc_list[MAX_IPC_NUM];
		int m_ipc_num;
};


typedef struct  str_thread_data
{
	int index; 
	SIP_SERVER * sip_svr;
}s_thread_param;


int SIP_SERVER::RegisterAction(osip_message_t *reg)
{
	int id;
	eXosip_lock ();
	id = eXosip_register_build_initial_register (LOCALSIP, HKREMOTESIP,	NULL,	7100, &reg);
	//osip_message_set_authorization(reg, "Capability algorithm=\"H:MD5\"");
	if (id < 0)
	{
		printf("exosip initial_register error!")
		eXosip_unlock ();
		return SIPERROR;
	}
	//osip_message_set_supported (reg, "100rel");
	//osip_message_set_supported(reg, "path");
	int retval = eXosip_register_send_register (id, reg);
	if(0 != retval)  
	{  
		printf("eXosip_register_send_register no authorization error!\r\n");  
		return -1;  
	}  
	printf("eXosip_register_send_register no authorization success!\r\n");  
	eXosip_unlock ();
	return id;
}

int SIP_SERVER::RegisterHeart(eXosip_event_t* je, int expires, osip_message_t* reg, char *strAuth ) //abandon
{
	int i;
	eXosip_lock ();
	i = eXosip_register_build_register (je->rid, expires, &reg);
	if (i < 0)
	{
		eXosip_unlock ();
		return -1;}
	osip_header_t *pMsgHeader=NULL;
	osip_message_header_get_byname(reg,(const char *)"authorization",0,&pMsgHeader);
	if (pMsgHeader==NULL)
		osip_message_set_header(reg,(const char *)"authorization", strAuth);
	else
		strcpy(pMsgHeader->hvalue, strAuth);
	eXosip_register_send_register (je->rid, reg);
	eXosip_unlock ();
}

int SIP_SERVER::RegisterWithAuthentication(osip_message_t* reg, eXosip_event_t* je )
{
	eXosip_lock();  
	eXosip_clear_authentication_info();
	eXosip_add_authentication_info("34020000001110000001", "34020000001110000001", "12345678", "MD5", NULL);
	eXosip_register_build_register(je->rid, 3600, &reg);  
	int retval = eXosip_register_send_register(je->rid, reg);  
	eXosip_unlock();  
	if(0 == retval)  
	{  
		printf("eXosip_register_send_register authorization error!\r\n");  
		return SIPERROR;  
	}  
	printf("eXosip_register_send_register authorization success!\r\n");  
	return SIPSUCCESS;
}

void SIP_SERVER::Register()
{
	
	eXosip_event_t *je  = NULL; 
	osip_message_t *invite = NULL; 
	osip_message_t *reg = NULL;  
	osip_message_t* heart_msg = NULL;
	int register_id = RegisterAction(reg);  
	for(;;)  
	{  
		je = eXosip_event_wait(0, 50);
		eXosip_lock();
		eXosip_automatic_action (); /*????non-200???????????SIP????Retry?????*/
		eXosip_automatic_refresh();/*Refresh REGISTER and SUBSCRIBE before the expiration delay*/
		eXosip_unlock();
		if(NULL == je)
		{  
			continue;  
		}  
		else if(EXOSIP_REGISTRATION_FAILURE == je->type)
		{  
			printf("<EXOSIP_REGISTRATION_FAILURE>\r\n");  
			PrintMsg(RESPONSE);
			if((NULL != je->response)&&(401 == je->response->status_code)) 
				RegisterWithAuthentication(reg, je);
			else
			{  
				printf("EXOSIP_REGISTRATION_FAILURE ERROR!\r\n");  
				break;
			}  
		}  
		else if(EXOSIP_REGISTRATION_SUCCESS == je->type)  
		{  
			printf("<EXOSIP_REGISTRATION_SUCCESS>\r\n");  
			PrintMsg(RESPONSE);
			register_id = je->rid;
			printf("register_id=%d\n", register_id);    
			break;
		}  
	} 
}
int SIP_SERVER::GetIpcVideoPortByIndex(int n)
{
	if(n < 0 || n >=  m_ipc_num)
	{
		return -1;
	}

	return ipc_list[n]->GetVideoPort();	

}

int SIP_SERVER::Search_Device_ByIP(char * p_ip)
{
	if(NULL == p_ip)
	{
		return -1;
	}
	int loop = 0;
	int index = -1;
	if(m_ipc_num > 0)
	{
		for(loop = 0; loop < m_ipc_num; loop++)
		{
			if(strcmp(p_ip, ipc_list[loop]->GetIP()) == 0)
			{
				index = loop;
				break;
			}
		}
	}
	return index;
	
}

void SIP_SERVER::GetLocalIP()
{
	

    int sock_get_ip;  
    char ipaddr[50];  
  
    struct   sockaddr_in *sin;  
    struct   ifreq ifr_ip;     
  
    if ((sock_get_ip=socket(AF_INET, SOCK_STREAM, 0)) == -1)  
    {  
         printf("socket create failse...GetLocalIp!/n");  
         return ;  
    }  
     
    memset(&ifr_ip, 0, sizeof(ifr_ip));     
    strncpy(ifr_ip.ifr_name, "eth0", sizeof(ifr_ip.ifr_name) - 1);     
   
    if( ioctl( sock_get_ip, SIOCGIFADDR, &ifr_ip) < 0 )     
    {     
         return;     
    }       
    sin = (struct sockaddr_in *)&ifr_ip.ifr_addr;
	memset(ipaddr, 0, sizeof(ipaddr));
    strcpy(ipaddr,inet_ntoa(sin->sin_addr));         
	memset(m_localsip, 0, sizeof(m_localsip));
	//memcpy(m_localsip, ipaddr, strlen(ipaddr));
	memset(m_ip, 0, sizeof(m_ip));
	memcpy(m_ip, ipaddr, strlen(ipaddr));
	
	snprintf(m_localsip, sizeof(m_localsip), "sip:%s@%s:%d", m_serverusr, m_ip, m_port);
	close( sock_get_ip );  
 
}


void  SIP_SERVER::OnRecVideoDataCallback(void * data, int len , int  data_len)
{
	if((NULL== data) || (len <= 0) || (data_len <= 0))
	{
		return;
	}
	while(len)
	{
		
		if(len >= data_len)
		{
			
			printf("\n recv data  len is %d \n", data_len);	
			
			len =  len - data_len;
		}
		else
		{
			printf("\n recv data  len is %d \n", data_len);
			break;
		}
		
	}

}


void SIP_IPC::ClearDeviceData()
{
	/* 数据全部清零 */
	memset(m_usr, 0, sizeof(m_usr));
	memset(m_pwd, 0, sizeof(m_pwd));
	memset(m_sn, 0, sizeof(m_sn));
	m_expire = 0;
	m_keepalive = 0;
}



char * SIP_IPC::GetIP()
{
	return m_ip;
}



char * SIP_IPC::GetRemoteSipSvr()
{
	printf("\n m_remotesip_srv is %s \n", m_remotesip_srv);
	return m_remotesip_srv;
}

void SIP_IPC::SetSipPort(int sip_port)
{
	if(sip_port <= 0)
	{
		m_sipport = DEFAULT_IPC_SIPSVR_PORT;	
	}
	else
	{
		m_sipport = sip_port;
	}
}


void SIP_IPC::SetIp(char * ip_addr)
{
	if(NULL == ip_addr)
	{
		//m_siprt = DEFAULT_IPC_SIPSVR_PORT;	
		printf("param ip is null ");
	}
	else
	{
		memcpy(m_ip, ip_addr, strlen(ip_addr));
	}
}


void SIP_IPC::BuildRemoteSipSvr()
{
	snprintf(m_remotesip_srv , sizeof(m_remotesip_srv), "sip:%s@%s:%d", m_usr, m_ip, m_sipport);
	printf("\n  m_remotesip_srv is %s \n", m_remotesip_srv);
}


void SIP_SERVER::RemoveDevice(int index)
{
	int loop = 0;

	if(index < 0 || index >= m_ipc_num)
	{
		printf("\n\n remove index is %d ipc num is  %d \n\n", index, m_ipc_num);
		return;	
	}
	/* 如果是最后一个设备，直接删除，如果不是最后一个，将现有的删除掉，后面的前移就可以 */
	if(index == (m_ipc_num - 1))
	{
		/* 直接删除最后一个元素 */
		delete ipc_list[index];
		m_ipc_num--;
	}
	else
	{
		
		/* 先清除当前数据 */
		ipc_list[index]->ClearDeviceData();
		char * cpydata = NULL;
		for(loop = index; loop < m_ipc_num; loop++)
		{
			/* 将数据前移，删除最后一个对象 */

			/* 用户名前移 */
			cpydata = ipc_list[loop+1]->GetUsr();
			ipc_list[loop]->SetUsr(cpydata);

			/* 密码前移 */
			cpydata = ipc_list[loop+1]->GetPwd();
			ipc_list[loop]->SetPwd(cpydata);

			/* sn前移 */
			cpydata = ipc_list[loop+1]->GetSN();
			ipc_list[loop]->SetSn(cpydata);
			/* expire 前移 */
			ipc_list[loop]->SetExpire(ipc_list[loop + 1]->GetExpire());
			/* keep alvie  前移 */
			ipc_list[loop]->SetKeepAlive(ipc_list[loop + 1]->GetKeepAlive());
			
		}	
		/* 删除最后一个对象 */
		delete ipc_list[m_ipc_num - 1];
		/* 设备数量减1 */
		m_ipc_num--;
	}
	

}

void SIP_IPC::SetExpire(int expire)
{
	if(expire > 0)
	{
		m_expire = expire;
	}
	else
	{
		m_expire = DEFAULT_KEEP_ALIVE;	
	}
	
}
	
/* 获取设备的 expire 信息 */
int SIP_IPC::GetExpire()
{
	return m_expire;
	
}

/* 获取设备的keep alive信息 */
int SIP_IPC::GetKeepAlive()
{
	return m_keepalive;
}


void SIP_IPC::UpdateKeepAlive()
{
	/* 将原始的expire值赋值 */
	m_keepalive = m_expire;
}

void SIP_SERVER::UpdateKeepAliveByDeviceID(char *device_id)
{
	if(NULL == device_id || (m_ipc_num == 0))
	{
		return;	
	}
	for(int loop = 0; loop < m_ipc_num; loop++)
	{
		if(strcmp(ipc_list[loop]->GetUsr(), device_id) == 0)
		{
			ipc_list[loop]->UpdateKeepAlive();	
		}
	}

}


void SIP_IPC::SetVideoPort(unsigned int port)
{

	m_videoport = port;
}

int SIP_IPC::GetVideoPort()
{
	printf("\n usr %s pwd %d port is %d \n",  m_usr, m_pwd, m_videoport);
	return m_videoport;
}



void SIP_IPC::SetKeepAlive(int keep_alive)
{
	m_keepalive = keep_alive;
}

/* 这里需要判断 */
int SIP_IPC::DecreaseKeepAlive()
{
	if(m_keepalive  > 0)
	{
		m_keepalive--;
	}
	else
	{
		m_keepalive = 0;	
	}
	//printf("\n\n  device %s \n  ip is %s \n  keepalive %d \n  srv_sip %s\n\n", m_usr, m_ip, m_keepalive, m_remotesip_srv);

	if(0 == m_keepalive)
	{
		return DEVICE_LOST;	
	}
	/* else ruturn  alive */
	return DEVICE_ALIVE;
	
}

void  * ThreadKeepAlive(void * data)
{
	
	if(NULL == data)
	{
		printf("\n data is null \n");	
	}
	else
	{
		SIP_SERVER * sip_svr = (SIP_SERVER *)data;
		sip_svr->ProcessKeepAlive();		
	}
	
    return((void*)0);
}

/*void  * ThreadSendKeepAlive(void * data)
{
	
	if(NULL == data)
	{
		printf("\n data is null \n");	
	}
	else
	{
		SIP_SERVER * sip_svr = (SIP_SERVER *)data;
		sip_svr->SendKeepAlive();		
	}
}*/




void  * ThreadManageDevice(void * data)
{
	if(NULL == data)
	{
		printf("\n data  null \n");	
	}
	else
	{
		SIP_SERVER * sip_svr = (SIP_SERVER *)data;
		sip_svr->DeviceManage();		
	}
}


/* 调用供后续使用的线程处理函数 */
/*void  ThreadRegister(void * data)
{
	if(NULL == sip_svr)
	{
		printf("\n sip svr null \n");	
	}
	else
	{
		SIP_SERVER * sip_svr = (SIP_SERVER *)data;
		sip_svr->Register();		
	}
}*/


int	SIP_SERVER::Is_device_Register(char * DeviceID)
{
	if((NULL == DeviceID)|| (this->m_ipc_num == 0))
	{
		return -1;	
	}
	int num = this->m_ipc_num;
	
	for(int loop = 0; loop < num; loop++)
	{
		if(strcmp(DeviceID, this->ipc_list[loop]->GetUsr()) == 0)
		{
			return loop;
		}

	}
	return -1;
	
}
/* device magage for ipc device  */
void  SIP_SERVER::DeviceManage()
{
	int loop = 0;
	while(1)
	{
		if(m_ipc_num > 0)
		{

			for(loop = 0; loop < m_ipc_num; loop++)
			{
				if(DEVICE_LOST == ipc_list[loop]->DecreaseKeepAlive())
				{
					this->RemoveDevice(loop);
					/* 判断删除后的值是否为0 */
					if(m_ipc_num <= 0)
					{
						break;
					}
				}				
			}
		}
		//printf("\n  $$$##$#$##### ready sleep  m_ipc_num is %d \n\n\n\n", m_ipc_num);

		sleep(1);/* linux下 调用sleep 单位是秒级 */
		

	}
}



int SIP_SERVER::Get_Ipc_Num()
{
	return this->m_ipc_num;
}

char*replace(char*src, char*sub, char*dst)
{
    int pos =0;
    int offset =0;
    int srcLen, subLen, dstLen;
    char*pRet = NULL;


    srcLen = strlen(src);
    subLen = strlen(sub);
    dstLen = strlen(dst);
    pRet = (char*)malloc(srcLen + dstLen - subLen +1);//(澶栭儴鏄惁璇ョ┖闂?if (NULL != pRet)
    {
        pos = strstr(src, sub) - src;
        memcpy(pRet, src, pos);
        offset += pos;
        memcpy(pRet + offset, dst, dstLen);
        offset += dstLen;
        memcpy(pRet + offset, src + pos + subLen, srcLen - pos - subLen);
        offset += srcLen - pos - subLen;
        *(pRet + offset) ='\0';
    }
    return pRet;
}
void SIP_SERVER::PTZ_Control_left(char* rsp_xml_body)
{
					snprintf(rsp_xml_body, 4096, 
					"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
					"<control>\r\n"
					"<CmdType>DeviceControl</CmdType>\r\n"
					"<SN>4</SN>\r\n"
					"<DeviceID>32010000001320000001</DeviceID>\r\n"
					"<PTZCmd>A50F0001E0E0F065</PTZCmd>\r\n"
					"</control>\r\n");
					
}

void SIP_SERVER::VideoFileQuery(char* rsp_xml_body)
{
					snprintf(rsp_xml_body, 4096, 
					"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
					"<Query>\r\n"
					"<CmdType>RecordInfo</CmdType>\r\n"
					"<SN>7</SN>\r\n"
					"<DeviceID>32010000001320000001</DeviceID>\r\n"
					"<StartTime>2019-04-24T00:00:00</StartTime>\r\n"
					"<EndTime>2019-04-24T23:59:59</EndTime>\r\n"
					"<Type>all</Type>\r\n"
					"</Query>\r\n");
					
}
void SIP_SERVER::Catalog(char* rsp_xml_body)
{
					snprintf(rsp_xml_body, 4096, 
					"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
					"<Query>\r\n"
					"<CmdType>Catalog</CmdType>\r\n"
					"<SN>7</SN>\r\n"
					"<DeviceID>32010000001320000001</DeviceID>\r\n"
					"</Query>\r\n");
					
}



int SIP_SERVER::Call_Build_Initial_Invite(int index,const char * rtp_svr, int rtp_svr_port)
{
		int i = -1;
		osip_message_t *invite = NULL;
		int inviteflag = 1;   
		char req_xml_body[4096] = {0};
		eXosip_event_t * je = NULL;
		int result = -1;
		int port = this->GetIpcVideoPortByIndex(index);
		
		printf("\n local ip is %s \n", m_localsip);
		/* 调用exsip接口 */

		i=eXosip_call_build_initial_invite(&invite,this->ipc_list[index]->GetRemoteSipSvr(), this->m_localsip, NULL, NULL);    

		if(i!=0)  
		{  
			printf("Initial INVITE failed!\n");  
			
			return  result;  
		}  

		osip_message_set_supported (invite, "100rel");
		/*100rel是临时响应的确认机制, 1xx临时响应，要求对端使用PRACK信令确认收到本信令
		收到PRACK后，本端针对PRACK相应200OK，便如三次握手*/
		memset(req_xml_body, 0, sizeof(req_xml_body));
		snprintf(req_xml_body, 4096,  
		"v=0\r\n"
		"o=34020000002000000001 0 0 IN IP4 %s\r\n"
		"s=Play\r\n"
		"c=IN IP4 %s\r\n"
		"t=0 0\r\n"
		"m=video %d RTP/AVP 96 98 97\r\n"
		"a=recvonly\r\n"
		"a=rtpmap:96 PS/90000\r\n"
		"a=rtpmap:98 H264/90000\r\n"
		"a=rtpmap:97 MPEG4/90000\r\n"
		"y=0100001001\r\n"
		, rtp_svr, rtp_svr, rtp_svr_port); 
		//"a=setup:passive\r\n"
		//"a=connection:new\r\n"
		osip_message_set_content_type(invite, "APPLICATION/SDP");
		osip_message_set_body(invite, req_xml_body, strlen(req_xml_body));				
		eXosip_lock();  
		i=eXosip_call_send_initial_invite(invite); //invite SIP INVITE message to send 
		eXosip_unlock();  
		while(inviteflag)  
		{  
			je  = eXosip_event_wait(0, 50); //Wait for an eXosip event  
			
			eXosip_lock();
			eXosip_execute();
			eXosip_automatic_action (); //部分non-200消息自动重发，SIP会话中Retry很常见
			eXosip_automatic_refresh();/*Refresh REGISTER and SUBSCRIBE before the expiration delay*/	
			eXosip_unlock();
			if(je == NULL)  
			{  
				//printf("No response or the time is over!\n");  
				result = -1;
				eXosip_execute();
				eXosip_automatic_action ();
				break;
			}  
			/* 这个时候不要设置上去 */
			//this->Set_je(je);
			/* 设置到IPC上 */
			//this->ipc_list[index]->Set_je(je);

			switch(je->type) 
			{  
				//case EXOSIP_CALL_PROCEEDING: 
					//printf("proceeding!\n");  
					//this->PrintMsg(RESPONSE);
					//break;  
				case EXOSIP_CALL_RINGING:  
					//printf("ringing!\n");  
					//this->PrintMsg(RESPONSE);
					//printf("call_id is %d,dialog_id is %d \n",je->cid,je->did);  
					break;  
				case EXOSIP_CALL_ANSWERED: 
					printf("  ~~~~~~~~~~~~~~~  ok!  connected!   ~~~~~~~~~~~~~~~~~~~\n");  
					//this->PrintMsg(RESPONSE);
					osip_message_t* ack;
					eXosip_call_build_ack(je->did,&ack);  
					eXosip_call_send_ack(je->did,ack);  
					inviteflag=0; //推出While循环  
					result = 0;
					break;  
				case EXOSIP_CALL_CLOSED: 
					printf("the other side closed!\n"); 
					this->PrintMsg(RESPONSE);
					break;  
				default:
					break;
			}  
		}
		/*  返回结果 */
		return result;
		
}




int SIP_SERVER::getserverport()
{
	return this->m_port;
}

void   SIP_BASIC::Set_je(eXosip_event_t * je)
{
	if(NULL !=  je)
	{
		this->m_je = je;		
	}

}

SIP_BASIC::~SIP_BASIC()
{
				
}

SIP_SERVER::~SIP_SERVER()
{
	/* 释放ipc 设备资源 */
	while(this->m_ipc_num > 0)
	{
		delete this->ipc_list[this->m_ipc_num - 1];
		this->m_ipc_num--;
	}
	eXosip_event_free(this->m_je);

}


char * SIP_IPC::GetSN()
{
	return this->m_sn;
};

char * SIP_IPC::GetUsr()
{
	return this->m_usr;
};



char * SIP_IPC::GetPwd()
{
	return this->m_pwd;
};


/*去掉字符串前后双引号*/
void SIP_BASIC::Remove_c(char * str)
{
	char remove='"';
	if (!str)
	{
		return;
	}
	int len = (int)strlen(str);
	if (len>256||len<2)
	{
		return;
	}
	if( str[len-1]==remove)
	{
		str[strlen(str)-1]='\0';
		len = (int)strlen(str);
		if (len<1)
		{
			return;
		}
	}
	if (str[0]==remove)
	{
		for (int i=0;i<len-1;i++)
		{
			str[i]=str[i+1];
		}
		str[len-1]='\0';
	}
}


/*回复设备远程启动查询*/
void SIP_IPC::SetUsr(char* usr)
{
		if(usr)
		{
			//printf("\n len is %d and is %s \n", strlen(usr), usr);
			memcpy(m_usr,  usr,  strlen(usr));
		}
		else
		{
				
		}
}


/*回复设备远程启动查询*/
void SIP_IPC::SetPwd(char* pwd)
{
		if(pwd)
		{
			memcpy(this->m_pwd,  pwd,  strlen(pwd));
		}
		else
		{
				printf("\n pwd input param is null \n");
		}
}



/* 设置sn */
void SIP_IPC::SetSn(char* Sn)
{
		if(Sn)
		{
			memcpy(m_sn,  Sn,  strlen(Sn));
		}
		else
		{
				printf("\n Sn input param is null \n");
		}
}




/*回复设备远程启动查询*/
void SIP_SERVER::PushDeviceCatalog(char* rsp_xml_body)
{
	printf("**************DEVICE CATALOG PUSH BEGIN***************\r\n");
	snprintf(rsp_xml_body,4096,"<?xml version=\"1.0\"?>\n"
		"<Notify>\r\n"
		"<CmdType>Catalog</CmdType>\r\n"
		"<SN>12345</SN>\r\n"
		"<DeviceID>32010000562000800001</DeviceID>\r\n"
		"<SumNum>1</SumNum>\r\n"
		"<DeviceList Num=\"1\">\r\n"
		"<Item>\r\n"
		"<DeviceID>32010000561310800001</DeviceID>\r\n"
		"<Name>Camera 16</Name>\r\n"
		"<Manufacturer>hik</Manufacturer>\r\n"
		"<CatalogType>1</CatalogType>\r\n"
		"<DecorderTag>hikvision-v3</DecorderTag>\r\n"
		"<RecLocation>2</RecLocation>\r\n"
		"<OperateType>ADD</OperateType>\r\n"
		"<Model>hik</Model>\r\n"
		"<Owner>hik</Owner>\r\n"
		"<CivilCode>32010000562000800001</CivilCode>\r\n"
		"<Block>1</Block>\r\n"
		"<Address>1</Address>\r\n"
		"<Parental>0</Parental>\r\n"
		"<ParentID>32010000562000800001</ParentID>\r\n"
		"<RegisterWay>1</RegisterWay>\r\n"
		"<CertNum>1</CertNum>\r\n"
		"<Certifiable>1</Certifiable>\r\n"
		"<ErrCode>400</ErrCode>\r\n"
		"<EndTime>2011-12-12T12:00:00</EndTime>\r\n"
		"<Secrecy>0</Secrecy>\r\n"
		"<Status>ON</Status>\r\n"
		"<IPAddress>127.0.0.1</IPAddress>\r\n"
		"<Port>8000</Port>\r\n"
		"<Password>12345</Password>\r\n"
		"<Longitude>0</Longitude>\r\n"
		"<Latitude>0</Latitude>\r\n"
		"<Info>\r\n"
		"<CameraType>1</CameraType>\r\n"
		"</Info>\r\n"
		"<Privilege>%03%03%00</Privilege>\r\n"
		"</Item>\r\n"
		"</DeviceList>\r\n"
		"</Notify>\r\n");
		//this->ipc_list[0]->GetSN(), this->ipc_list[0]->GetUsr());
}
void SIP_SERVER::ResponseDeviceBoot(char* rsp_xml_body)
{
		printf("**********DEVICE STATUS BEGIN**********\r\n");	

		snprintf(rsp_xml_body, 4096, "<?xml version=\"1.0\"?>\r\n"
		"<Response>\r\n"
		"<CmdType>DeviceStatus</CmdType>\r\n"
		"<SN>%s</SN>\r\n"
		"<DeviceID>%s</DeviceID>\r\n"
		"<Result>OK</Result>\r\n"
		"</Response>\r\n",
		this->ipc_list[0]->GetSN() , this->ipc_list[0]->GetUsr());
}

/*回复设备状态查询*/
void SIP_SERVER::ResponseDeviceStatus(char* rsp_xml_body)
{
		printf("**********DEVICE STATUS BEGIN**********\r\n");	
		time_t rawtime;
		struct tm* timeinfo;
		time(&rawtime);
		timeinfo = localtime(&rawtime);
		char curtime[72] = {0};
		sprintf(curtime, "%d-%d-%dT%02d:%02d:%02d", (timeinfo->tm_year + 1900), (timeinfo->tm_mon + 1), timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
		snprintf(rsp_xml_body, 4096, "<?xml version=\"1.0\"?>\r\n"
		"<Response>\r\n"
		"<CmdType>DeviceStatus</CmdType>\r\n"
		"<SN>%s</SN>\r\n"
		"<DeviceID>%s</DeviceID>\r\n"
		"<Result>OK</Result>\r\n"
		"<Online>ONLINE</Online>\r\n"
		"<Status>OK</Status>\r\n"
		"<DeviceTime>%s</DeviceTime>\r\n"
		"<Alarmstatus Num=\"0\">\r\n"
		"</Alarmstatus>\r\n"	
		"<Encode>ON</Encode>\r\n"	
		"<Record>OFF</Record>\r\n"	
		"</Response>\r\n",
		this->ipc_list[0]->GetSN(), this->ipc_list[0]->GetUsr(), curtime);
	}

	/*回复设备目录查询*/
	void SIP_SERVER::ResponseCatalog(char* rsp_xml_body)
	{
			printf("**********CATALOG BEGIN**********\r\n");	
			snprintf(rsp_xml_body, 4096, "<?xml version=\"1.0\"?>\r\n"
			"<Response>\r\n"
			"<CmdType>Catalog</CmdType>\r\n"
			"<SN>1</SN>\r\n"
			"<DeviceID>32010000001120000001</DeviceID>\r\n"
			"<SumNum>1</SumNum>\r\n"
			"<DeviceList Num=\"1\">\r\n"
			"<Item>\r\n"
			"<DeviceID>32010000001320000001</DeviceID>\r\n"
			"<Name>simulate client</Name>\r\n"
			"<Manufacturer>HighWayBit</Manufacturer>\r\n"
			"<Model>28181</Model>\r\n"
			"<Owner>Owner</Owner>\r\n"
			"<CivilCode>CivilCode</CivilCode>\r\n"
			"<Address>Address</Address>\r\n"
			"<Parental>0</Parental>\r\n"
			"<ParentID>32010000001120000001</ParentID>\r\n"
			"<SafetyWay>0</SafetyWay>\r\n"
			"<RegisterWay>1</RegisterWay>\r\n"
			"<Secrecy>0</Secrecy>\r\n"
			"<Status>ON</Status>\r\n"
			"</Item>\r\n"
			"</DeviceList>\r\n"
			"</Response>\r\n"
			/*this->ipc_list[0]->GetSN()/*, this->ipc_list[0]->GetUsr(), this->ipc_list[0]->GetUsr()*/);
	}

/*响应180Ringing*/
void SIP_BASIC::Answer180( )
{
	eXosip_lock ();
	eXosip_call_send_answer (this->m_je->tid, 180, NULL);
	eXosip_unlock ();
}

/*回应200 OK*/
void SIP_BASIC::Answer200()
{
	osip_message_t *answer = NULL;
	eXosip_lock ();
	eXosip_message_build_answer (this->m_je->tid, 200, &answer);
	eXosip_message_send_answer (this->m_je->tid, 200, answer);
	eXosip_unlock ();
	//printf("**********  ANSWER 200 OK  **********\n");
}


/*处理Register*/
int SIP_SERVER::ProcessRegister()
{
	osip_message_t* asw_register= NULL;
	//Define authentication variables
	char WWW_Authenticate[512]={0};
#if 1	
	char *pszAlg = "md5";
	char *pszUserName = "";
	char *pszPassword = "";
	char *pszRealm = "10.0.0.4";
	char *pszMethod = "REGISTER";
	char *pszDigestUri = "";
	char *pszCNonce = "";
	char *pszNonceCount = "";
	char *pszQop = "";
	int Aka = 0;
	HASHHEX SessionKey = "";
	HASHHEX HEntity = "";
	HASHHEX Response;
	char * response_h="";
#else
	char *pszAlg = NULL;
	char *pszUserName =NULL;
	char *pszPassword = NULL;
	char *pszRealm = NULL;
	const char *pszMethod = "REGISTER";
	char *pszDigestUri =NULL;
	char *pszCNonce = NULL;
	char *pszNonceCount = NULL;
	char *pszQop = NULL;
	int Aka = 0;
	HASHHEX SessionKey = NULL;
	HASHHEX HEntity = "";
	HASHHEX Response;
	char * response_h="";
#endif
	
	//Get Authentication Info from last response
	osip_authorization_t *AuthHeader;
	osip_message_get_authorization(this->m_je->request,0,&AuthHeader);

	/* 第一次的认证返回信息 */
	if (!AuthHeader) //Question
	{
		printf("\n this m_Nonce is %s \n", m_Nonce);

		sprintf(WWW_Authenticate, "Digest realm=\"10.0.0.4\",algorithm=MD5,nonce=\"%s\"", m_Nonce);
		eXosip_lock ();
		eXosip_default_action(this->m_je);
		eXosip_message_build_answer (this->m_je->tid, 401, &asw_register);
		osip_message_set_header(asw_register,"WWW-Authenticate",WWW_Authenticate);
		eXosip_message_send_answer (this->m_je->tid, 401, asw_register);

		eXosip_unlock ();
	}
	else //Test and Verify
	{
		pszPassword = "12345678";
		pszRealm = "10.0.0.4";
		pszAlg = AuthHeader->algorithm==NULL?NULL:AuthHeader->algorithm;
		pszUserName = AuthHeader->username==NULL?NULL:AuthHeader->username;
		pszDigestUri = AuthHeader->uri==NULL?NULL:AuthHeader->uri;
		pszNonceCount=AuthHeader->nonce_count==NULL?NULL:AuthHeader->nonce_count;
		pszQop = AuthHeader->opaque==NULL?NULL:AuthHeader->opaque;
		response_h = AuthHeader->response==NULL?NULL:AuthHeader->response;			
		//Remove the double quotation marks at the first&last place
		this->Remove_c(pszAlg);
		this->Remove_c(pszUserName);
		this->Remove_c(pszDigestUri);
		this->Remove_c(pszQop);
		this->Remove_c(pszNonceCount);
		this->Remove_c(response_h);
		/* 加密关键字信息 */
		//printf("\n pszPassword is %s \n pszUserName is %s \n m_Nonce %s \n pszCNonce \n", pszPassword, pszUserName,  this->m_Nonce);
		DigestCalcHA1(pszAlg, pszUserName, pszRealm, pszPassword, m_Nonce, pszCNonce,  SessionKey);
		DigestCalcResponse(SessionKey,  m_Nonce, pszNonceCount, pszCNonce,  pszQop, Aka, pszMethod,pszDigestUri, HEntity, Response);
		if (!strcmp(Response, response_h))
		{
			printf("\n  Authentication  Ok   !!! \n");

			/* 获取注册的保活有效期 */
			 osip_header_t* header = NULL;
		     int expires = 0;
	         osip_message_header_get_byname(this->m_je->request, "expires", 
	                 0, &header);
	        if (NULL != header && NULL != header->hvalue)
	        {
	             printf("this expires is %d  \n\n", atoi(header->hvalue));
				 expires =  atoi(header->hvalue);
	        }
			else
			{
				expires = DEFAULT_KEEP_ALIVE;	
			}

			/* 需要先提取请求的数据 */
			osip_contact_t * p_contact  = NULL;
			osip_message_get_contact(this->m_je->request, 0,  &p_contact);

			eXosip_lock ();
			//eXosip_default_action(this->m_je);
			eXosip_message_build_answer (this->m_je->tid, 200, &asw_register);
			eXosip_message_send_answer (this->m_je->tid, 200, asw_register);

			int index = this->Is_device_Register(pszUserName);
			int index_ipc_svr = 0;

			/* 设备如果没有注册的情况下 需要注册 */
			if(-1 == index)
			{
					//SIP_IPC ipc;
				if(this->m_ipc_num >= MAX_IPC_NUM)
				{
						this->m_ipc_num -= MAX_IPC_NUM;
				}
				/* 需要重复覆盖时，需要注意将原有的对象释放掉 */
				if(this->ipc_list[this->m_ipc_num-1])
				{
				    printf("gy666");
					//this->ipc_list[this->m_ipc_num] = NULL;
					delete 	this->ipc_list[this->m_ipc_num-1];
					//delete ipc_list[this->m_ipc_num];
					//this->ipc_list[this->m_ipc_num] = NULL;
					
				}
				this->ipc_list[this->m_ipc_num] = new SIP_IPC;
				/* 将一些关键的子变量赋值到类上 */
				/* 用户名 */
				this->ipc_list[this->m_ipc_num]->SetUsr(pszUserName);
				/* 端口配置 */
				//this->ipc_list[this->m_ipc_num]->m_videoport = VIDEOPORT;	
				this->ipc_list[this->m_ipc_num]->SetVideoPort(g_video_port++);
				/* 密码 */
				this->ipc_list[this->m_ipc_num]->SetPwd(pszPassword);
				/* 设置注册设备默认值 */
				this->ipc_list[this->m_ipc_num]->SetExpire(expires);
				/* 更新心跳信息 */
				this->ipc_list[this->m_ipc_num]->UpdateKeepAlive();

				/*  先记录再加1 操作 */
				index_ipc_svr = this->m_ipc_num;
				

				this->m_ipc_num++;
			}
			else
			{
				/* 已经注册的情况下不再增加设备 更新其他信息  密码 video 端口 以及expire */
				//this->ipc_list[this->m_ipc_num]->m_videoport = VIDEOPORT;	
				//this->ipc_list[this->m_ipc_num]->SetVideoPort(VIDEOPORT);
				this->ipc_list[index]->SetVideoPort(g_video_port++);
				/* 密码 */
				this->ipc_list[index]->SetPwd(pszPassword);
				/* 设置注册设备默认值 */
				this->ipc_list[index]->SetExpire(expires);
					/* 更新心跳信息 */
				this->ipc_list[index]->UpdateKeepAlive();
				/* 记录需要更新的ipc svr的 index */
				index_ipc_svr = index;
			}
			
			
			if (NULL != p_contact)
			{
					printf("thi p_contact is not null  \n\n");
						/* 设置端口 */
					this->ipc_list[index_ipc_svr]->SetSipPort(atoi(p_contact->url->port));
					/* 设置IP  */
					this->ipc_list[index_ipc_svr]->SetIp(p_contact->url->host);

					/* 最后一步更新组建Remote Sip SVR */
					this->ipc_list[index_ipc_svr]->BuildRemoteSipSvr();
				
			}
			else
			{
				
			}
			eXosip_unlock ();


		}
	//Then store the UserID and show it. Use it for redirect or find route.
	}  // Extract the "expires" , 0 means logout, >0 should be stored and monitor time.
	return SIPSUCCESS;
}

/*处理Invite*/
int SIP_SERVER::ProcessInvite()
{
		osip_message_t* asw_invite= NULL;/*请求的确认型应答*/
		char sdp_body[4096] = {0};
		eXosip_lock();
		if(0 != eXosip_call_build_answer(this->m_je->tid, 200, &asw_invite))/*Build default Answer for request*/
		{
			eXosip_call_send_answer(this->m_je->tid, 603, NULL);
			eXosip_unlock();
			printf("eXosip_call_build_answer error!\r\n");
			return SIPERROR;
		}
		eXosip_unlock();

		snprintf(sdp_body, 4096, "v=0\r\n"/*协议版本*/
		"o=32032200001120000001 0 0 IN IP4 221.226.150.236\r\n"/*会话源*//*用户名/会话ID/版本/网络类型/地址类型/地址*/
		"s=Embedded IPC\r\n"/*会话名*/
		"c=IN IP4 221.226.150.236\r\n"/*连接信息*//*网络类型/地址信息/多点会议的地址*/
		"t=0 0\r\n"/*时间*//*开始时间/结束时间*/
		"m=video %d RTP/AVP 96\r\n"/*媒体/端口/传送层协议/格式列表*/
		"a=sendonly\r\n"/*收发模式*/
		"a=rtpmap:96 PS/90000\r\n"/*净荷类型/编码名/时钟速率*/
		"a=username:32032200001120000001\r\n"
		"a=password:12345678\r\n"
		"y=100000001\r\n"
		"f=\r\n", 15060);
		eXosip_lock();
		osip_message_set_body(asw_invite, sdp_body, strlen(sdp_body));
		osip_message_set_content_type(asw_invite, "application/sdp");
		eXosip_call_send_answer(this->m_je->tid, 200, asw_invite);
		printf("eXosip_call_send_answer  success!\r\n");
		eXosip_unlock();
		
		if(Get_Ipc_Num() > 0)
			{
		Call_Build_Initial_Invite(0, "202.102.101.161", 20008);
		}
			
		return SIPSUCCESS;
}

void   SIP_SERVER::SendKeepAlive()
{	
	printf("send heartbeat1\n");
	char req_xml_body[4096] = {0};
	osip_message_t* heart_msg = NULL;
	memset(req_xml_body, 0, sizeof(req_xml_body));
	snprintf(req_xml_body, 4096, 
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		"<Notify>\r\n"
		"<CmdType>Keepalive</CmdType>\r\n"
		"<SN>4</SN>\r\n"
		"<DeviceID>654321</DeviceID>\r\n"
		"<Status>OK</Status>\r\n"
		"</Notify>\r\n");
	eXosip_message_build_request(&heart_msg, "MESSAGE", HKREMOTESIP, LOCALSIP, NULL); 
	osip_message_set_body(heart_msg, req_xml_body, strlen(req_xml_body));
	osip_message_set_content_type(heart_msg, "Application/MANSCDP+xml");
	eXosip_message_send_request(heart_msg);
		
}
void   SIP_SERVER::ProcessKeepAlive()
{
	eXosip_event_t * je;
	osip_message_t *reg = NULL;
	int register_id ;//= RegisterAction(reg);
	while(1)
	{
		je = eXosip_event_wait(0, 50);
		eXosip_lock();
		eXosip_automatic_action (); //部分non-200消息自动重发，SIP会话中Retry很常见
		eXosip_automatic_refresh();/*Refresh REGISTER and SUBSCRIBE before the expiration delay*/	
		eXosip_unlock();
		
		if(NULL == je)
		{  
				continue;  
		}  
		else
		{
					/* 增加赋值操作 */
			       //printf("je is not null \n\n");
					
				this->Set_je(je);

				if (EXOSIP_CALL_INVITE == je->type)
				{
					if(MSG_IS_INVITE(je->request))
					{   //osip_body_t* invie_req_body = NULL;

						invie_req_body = NULL;

						osip_message_get_body(je->request, 0, &invie_req_body);
						this->PrintMsg(REQUEST);
						this->ProcessInvite();
					}
				}
				else if(EXOSIP_REGISTRATION_FAILURE == je->type)
		        {  
			         printf("<EXOSIP_REGISTRATION_FAILURE>\r\n");  
			         PrintMsg(RESPONSE);
			         if((NULL != je->response)&&(401 == je->response->status_code)) 
				     RegisterWithAuthentication(reg, je);
			         else
			         {  
				     printf("EXOSIP_REGISTRATION_FAILURE ERROR!\r\n");  
				
			         }  
		        }  
		else if(EXOSIP_REGISTRATION_SUCCESS == je->type)  
		{  
			printf("<EXOSIP_REGISTRATION_SUCCESS>\r\n");  
			PrintMsg(RESPONSE);
			register_id = je->rid;
			printf("register_id=%d\n", register_id);
			
	
		} 
		else if(EXOSIP_IN_SUBSCRIPTION_NEW == je->type)
			{
				if(MSG_IS_SUBSCRIBE(je->request))
						{
							printf("MSG_IS_SUBSCRIBE\n");
							osip_message_t* subscribe = NULL;
			                int i=eXosip_insubscription_build_answer (this->m_je->tid, 200, &subscribe);
			                int a=eXosip_insubscription_send_answer (this->m_je->tid, 200, subscribe);
						}
			
			}
		else if (EXOSIP_MESSAGE_NEW == je->type)
		    {
						

						if (MSG_IS_REGISTER(je->request))
						{   printf("ProcessRegister");
							this->ProcessRegister();
						}
						/*else if(MSG_IS_SUBSCRIBE(je->request))
						{
							printf("MSG_IS_SUBSCRIBE\n");
							this->Answer200();
						}*/
						else if(MSG_IS_NOTIFY(je->request))
						{
							printf("MSG_IS_NOTIFY\n");
							this->Answer200();
						}
						else if(MSG_IS_MESSAGE(je->request))
						{

							osip_body_t* req_body = NULL;
							osip_message_get_body(je->request, 0, &req_body);
							char CmdType[99] = {0}, TeleBoot[99] = {0},  rsp_xml_body[4096] = {0};
							char Sn[100] = {0};
							char DeviceID[100] = {0};
							this->get_str(req_body->body, "<CmdType>", false, "</CmdType>", false, CmdType);

							this->get_str(req_body->body, "<SN>", false, "</SN>", false, Sn);
							this->get_str(req_body->body, "<DeviceID>", false, "</DeviceID>", false, DeviceID);

							//printf("The three elements : CmdType~%s, SN~%s,DeviceID~%s\n", CmdType,  Sn, DeviceID);

							/* 已经注册的信息才返回，否则不返回  */
							if(1/*this->Is_device_Register(DeviceID) != -1*/)
							{
								this->Answer200();
								this->UpdateKeepAliveByDeviceID(DeviceID);

								if(strcmp(CmdType, "DeviceInfo") == 0)
								{
									this->ResponseDeviceInfo(rsp_xml_body);
								}
								else if (strcmp(CmdType, "Catalog") == 0)
								{	printf("\n ######  receive message is Catalog \n");
									this->ResponseCatalog(rsp_xml_body);
								}
								else if (strcmp(CmdType, "DeviceStatus") == 0)
								{
									this->ResponseDeviceStatus(rsp_xml_body);
								}
								else if (strcmp(CmdType, "DeviceControl") == 0)
								{
									this->get_str(req_body->body, "<TeleBoot>", false, "</TeleBoot>", false, TeleBoot);
									if ((*TeleBoot != NULL) && (strcmp(TeleBoot, "Boot") == 0))
									{
										this->ResponseDeviceBoot(rsp_xml_body);
									}
								}
								else if (strcmp(CmdType, "Keepalive") == 0)
								{
									
								}
								else
								{
									printf("\n 3######  receive message is %s \n", CmdType);
								}
								//Function Calls below would not happened in case of PTZ or FI messages.  Just extract the commands contained and move IPCs.
								
								osip_message_t* rsp_msg = NULL;
								eXosip_message_build_request(&rsp_msg, "MESSAGE", HKREMOTESIP, LOCALSIP, NULL);
								osip_message_set_body(rsp_msg, rsp_xml_body, strlen(rsp_xml_body));
								osip_message_set_content_type(rsp_msg, "Application/MANSCDP+xml");
								eXosip_message_send_request(rsp_msg);		
								//printf(" eXosip_message_send_request success! \r\n");
							}
							else
							{
								//printf(" @@@@@@@@@@@@@@@@ device not register ! @@@@@@@@@@@@@@@  \r\n");
							}	
						}		
					} 
					else if (EXOSIP_CALL_ACK == je->type)
					{
						this->PrintMsg(REQUEST);
						printf("<EXOSIP_CALL_ACK>\r\n");  
					}
					else if (EXOSIP_CALL_CLOSED == je->type)
					{
						this->PrintMsg(REQUEST);
						printf("<EXOSIP_CALL_CLOSED>\r\n");  
					}
					else if((EXOSIP_CALL_ANSWERED == je->type) || (EXOSIP_MESSAGE_ANSWERED == je->type) )
					{
						printf("\n\n\n   22222222222222   text info  is %s  22222222222222222 \n", je->textinfo);
						osip_message_t* ack;
						eXosip_call_build_ack(je->did, &ack);  
						eXosip_call_send_ack(je->did, ack);  
					}
					else
					{	
						//printf("\n\n\ other @@@@@  text inf   is %s \n",je->textinfo);
						
					}
			}
	}
}



void    SIP_SERVER::ProcessRTPDataToPS(int * p_port)
{
		int sock;
		if(NULL == p_port)
		{
			printf("p_port is null!");
			return ;
		}
		if((sock = socket(AF_INET, SOCK_DGRAM, 0))<0)
		{
			printf("create socket error!");
			return ;
		}
		printf("socket sock=%d port is %d\n",sock, *p_port);

		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		//bzero(&addr,sizeof(addr));
		addr.sin_family=AF_INET;
		addr.sin_port=htons(*p_port);
		addr.sin_addr.s_addr=htonl(INADDR_ANY);

		int r = -1;
		int fd = sock;

		r=bind(fd,(struct sockaddr*)&addr,sizeof(addr));
		if(r==-1)
		{
			printf("Bind error!\n");
			close(fd);
			exit(-1);
		}
		
		printf("Bind successfully.\n");

		char buf[MAX_LEN];
		struct sockaddr_in from;
		socklen_t len;
		len=sizeof(from);
		//int m_flag = 0;
		//char 
		while(1)
		{
			//printf("准备接受数据··\n");
			
			memset(buf, 0, sizeof(buf));
			r=recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)&from, &len);//成功则返回接收到的字符数,失败返回-1.
			
			if(r<0)
			{
				continue;
			}
			
			printf("\n port is %d \n", *p_port);	
			
			OnRecVideoDataCallback(buf, r, sizeof(buf));
			
		}
		close(fd);
}


void  * Call_Build_Initial_Invite(void * data)
{
	if(NULL == data)
	{
		printf("\n  data is null \n");
	}
	else
	{
		//SIP_SERVER * sip_svr = (SIP_SERVER *)data;

		s_thread_param * p_thread_param= (s_thread_param *)data;

		SIP_SERVER * sip_svr = p_thread_param->sip_svr;

		int index = p_thread_param->index;
		
		
		(void)sip_svr->Call_Build_Initial_Invite(index,"172.28.106.129",8402);	

	}
}



void * ProcessRTPDataToPS(void * data)
{
	
	if(NULL == data)
	{
		printf("\n  data is null \n");
	}
	else
	{
		//SIP_SERVER * sip_svr = (SIP_SERVER *)data;

		s_thread_param * p_thread_param= (s_thread_param *)data;

		SIP_SERVER * sip_svr = p_thread_param->sip_svr;
			
		if(NULL != sip_svr)
		{	
				int num = sip_svr->Get_Ipc_Num();
		
				int port = 0;

				if(0 == num)
				{
					port = VIDEOPORT;
				}
				else
				{
					port = sip_svr->GetIpcVideoPortByIndex(g_thread_index++);
					if(g_thread_index >=  sip_svr->Get_Ipc_Num())
					{
						g_thread_index = 0;
					}
				}
				sip_svr->ProcessRTPDataToPS(&port);	
		}
				
	}
	while(1)
	{
		sleep(10);			
	}
}



/*eXoisp初始化*/
int SIP_SERVER::eXosipInitialize()
{
		TRACE_INITIALIZE (6, stdout); //initialize log file
		int i=0;
		i=eXosip_init();  
		if(i!=0)  
		{  
			printf("Couldn't initialize eXosip!\n");  
			return SIPERROR;  
		}  
		else  
		{  
			printf("eXosip_init successfully!\n");  
		}  

		i=eXosip_listen_addr(IPPROTO_UDP, NULL, this->m_port, AF_INET,0);  //initialize transport layer
		if(i!=0)  
		{  
			eXosip_quit();  
			fprintf(stderr,"Couldn't initialize transport layer!\n");  
			return SIPERROR;  
		} 
		return SIPSUCCESS;
}


/*eXoisp初始化*/

int SIP_SERVER::Init_Server()
{
	int ret = -1;
	ret = this->eXosipInitialize();
	if(SIPSUCCESS  !=  ret)
	{
		printf("\n   ret is %d  \n", ret);
		return ret;
	}
	else
	{
		printf("\n   eXosipInitialize sucess  \n");
	}

	return ret;
}


/*打印Sip消息*/
int SIP_BASIC::PrintMsg(int ch)
{
	char *dest=NULL;
	size_t length=0;
	int i=0;
	if (ch == 1)
	{
		i = osip_message_to_str(this->m_je->request, &dest, &length);
	}	
	else if(ch == 0)
	{	
		i = osip_message_to_str(this->m_je->response, &dest, &length);
	}
	if (i!=0)
	{ 
		printf("cannot get printable message\n");
		return SIPERROR; 
	}
	printf("/****************New Sip Message****************/\n");
	if(dest)
	{
		printf("%s\n", dest);
	}
	printf("/****************Sip Message End****************/\n");
	osip_free(dest);
	return SIPSUCCESS;
}



/*获取中间某字符串*/
int SIP_BASIC::get_str( const char* data, const char* s_mark, bool with_s_make, const char* e_mark, bool with_e_make, char* dest )
{
	const char* satrt = strstr( data, s_mark );
	if( satrt != NULL )
	{
		const char* end = strstr( satrt, e_mark );
		if( end != NULL )
		{
			int s_pos = with_s_make ? 0 : strlen(s_mark);
			int e_pos = with_e_make ? strlen(e_mark) : 0;
			strncpy( dest, satrt+s_pos, (end+e_pos) - (satrt+s_pos) );
		}
		return 0;
	}
	return -1;
}

/*回复设备信息查询*/
void SIP_SERVER::ResponseDeviceInfo(char* rsp_xml_body)
{
	printf("**********DEVICE INFO BEGIN**********\r\n");	/*设备信息查询*/
	snprintf(rsp_xml_body, 4096, "<?xml version=\"1.0\"?>\r\n"
	"<Response>\r\n"
	"<CmdType>DeviceInfo</CmdType>\r\n"/*命令类型*/
	"<SN>%s</SN>\r\n"/*命令序列号*/
	"<DeviceID>%s</DeviceID>\r\n"/*目标设备/区域/系统的编码*/
	"<Result>OK</Result>\r\n"/*查询结果*/
	"<DeviceType>simulate client</DeviceType>\r\n"
	"<Manufacturer>HighWayBit</Manufacturer>\r\n"/*设备生产商*/
	"<Model>28181</Model>\r\n"/*设备型号*/
	"<Firmware>fireware</Firmware>\r\n"/*设备固件版本*/
	"<MaxCamera>1</MaxCamera>\r\n"	
	"<MaxAlarm>0</MaxAlarm>\r\n"			
	"</Response>\r\n",
	this->ipc_list[0]->GetSN(), this->ipc_list[0]->GetUsr());
}


/*回复设备信息查询*/
void SIP_SERVER::GenerateRadom()
{
	
	//char* random = (char*)calloc(8, sizeof(char));
	char nonce[16] = {0};
	char  * random = new char[8];
	if(NULL == random )
	{
		printf("\n random is null \n");
		return;
	}
	memset(nonce, 0,  sizeof(nonce));
	/* 调用函数生成随机数 */
	eXosip_generate_random(random, sizeof(char)*8);
	memset(m_Nonce, 0, sizeof(m_Nonce));
	sprintf(m_Nonce, "%02x%02x%02x%02x%02x%02x%02x%02x", random[0], random[1], random[2], random[3],random[4],random[5] ,random[6] ,random[7]);
	
	/* 删除new生成的对象 */
	delete random;
	return;
}


/*回复设备信息查询*/
char * SIP_SERVER::GetNonce()
{
	return this->m_Nonce;
}

	
int main (int argc, char *argv[])  
{  
	/*Redis *r = new Redis();
	if(!r->connect("127.0.0.1", 6379))
    {
        printf("connect error!\n");
        return 0;
    }
	else
	{
		printf("connect success!\n");
	}*/


	SIP_SERVER  sip_svr;

	sip_svr.Init_Server();

	 pthread_t ntid;
	
	if (pthread_create(&ntid, NULL, ThreadKeepAlive, (void*)&sip_svr))
	{
		printf("error：CreateThread failed！\n");
		return -1;
	}
	/* 对应的线程起来 */
	if (pthread_create(&ntid, NULL, ThreadManageDevice, (void*)&sip_svr))
	{
		printf("error：CreateThread failed！\n");
		return -1;
	}

	/*while(sip_svr.Get_Ipc_Num() <= 0)
	{
			printf("\n no device register!!  \n");
			sleep(3);	
	}*/
	
	
	int  flag=1;   
	char command ;
	int loop = 0;
	char req_xml_body[4096] = {0};
	s_thread_param  thread_param;

	
	for(loop = 0; loop < sip_svr.Get_Ipc_Num(); loop++)
	{
		thread_param.index = loop;
		thread_param.sip_svr = &sip_svr;
		
		if (pthread_create(&ntid, NULL, ProcessRTPDataToPS, (void*)&thread_param))
		{
			printf("error：CreateThread failed！\n");
			return -1;
		}
	}
	while(flag)  
	{  		/*char req_xml_body[4096] = {0};
	printf("send heartbeat1\n");
	
	osip_message_t* heart_msg = NULL;
	memset(req_xml_body, 0, sizeof(req_xml_body));
	
	snprintf(req_xml_body, 4096, 
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		"<Notify>\r\n"
		"<CmdType>Keepalive</CmdType>\r\n"
		"<SN>4</SN>\r\n"
		"<DeviceID>654321</DeviceID>\r\n"
		"<Status>OK</Status>\r\n"
		"</Notify>\r\n");
	eXosip_message_build_request(&heart_msg, "MESSAGE", HKREMOTESIP, LOCALSIP, NULL); 
	osip_message_set_body(heart_msg, req_xml_body, strlen(req_xml_body));
	osip_message_set_content_type(heart_msg, "Application/MANSCDP+xml");
	int qqq=eXosip_message_send_request(heart_msg);
	printf("%d",qqq);
	sleep(3);*/
			printf("Please input the command:\n");  
			scanf("%c",&command);  
			getchar();  
			switch(command)  
			{  
				case 'a': 
#if 1	
						printf("\n $$$$$$$$   index   @@@@@@@@@@@@@  is %d \n", loop);
						sip_svr.Call_Build_Initial_Invite(loop,"192.168.75.112",8402);
				
#endif
					//sip_svr.Call_Build_Initial_Invite(SAMPLE_INDEX);
					//printf("\n $$$$$$$$   index  @@@@@@@@@@@@@  is %d \n", loop);
					break;
				case 'b':
									
									{printf("catalog start!\n");
									sip_svr.Catalog(req_xml_body); 
									osip_message_t* pushdevice = NULL;
									eXosip_message_build_request(&pushdevice, "MESSAGE", REMOTESIP, LOCALSIP, NULL);	
									osip_message_set_body(pushdevice, req_xml_body, strlen(req_xml_body));
									osip_message_set_content_type(pushdevice, "Application/MANSCDP+xml");
									eXosip_message_send_request(pushdevice);}
									break;

				case 'c':
					{printf("push video query start!\n");
					sip_svr.VideoFileQuery(req_xml_body); 
					osip_message_t* pushdevice = NULL;
					eXosip_message_build_request(&pushdevice, "MESSAGE", REMOTESIP, LOCALSIP, NULL);	
					osip_message_set_body(pushdevice, req_xml_body, strlen(req_xml_body));
					osip_message_set_content_type(pushdevice, "Application/MANSCDP+xml");
					eXosip_message_send_request(pushdevice);}
					break;
				case 'd':       
					printf("Hang Up!\n");  
					eXosip_lock();  
					eXosip_call_terminate(sip_svr.m_je->cid, sip_svr.m_je->did);  
					eXosip_unlock();  
					break; 
				case 'e':
					{
					
					printf("push device Catalog start!\n");
					sip_svr.PushDeviceCatalog(req_xml_body);
					osip_message_t* pushdevice = NULL;
					eXosip_message_build_request(&pushdevice, "NOTIFY", REMOTESIP, LOCALSIP, NULL);	
					osip_message_set_body(pushdevice, req_xml_body, strlen(req_xml_body));
					osip_message_set_content_type(pushdevice, "Application/MANSCDP+xml");
					eXosip_message_send_request(pushdevice);
					
					}
					break;
					
				case 'f':  
					eXosip_quit();  
					printf("Exit the setup!\n");  
					flag=0;  
					break;  
				case 'g':
					printf("\n\n num of device is %d\n\n", sip_svr.Get_Ipc_Num());
					break;
				}  
	}
	while(1)
	{
			printf("\n should not in this case  \n");
			sleep(3);	
	}
	return  0; 
}

