#include <iostream>
#include <sstream>
#include <string.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <fnmatch.h>
#include <unistd.h>
#include <pthread.h>
#include <algorithm>
//#include <stdio.h>

#include "PacketProcess.h"
#include <pcap.h>
#include "ThreadPool.h"
#include "data/SystemData.h"
#include "data/DomainRuleNode.h"
#include "include/common_type.h"

using std::string;
using std::cout;
using std::endl;

#define COMMONHEADER_1          "HTTP/1.1 302 Found\r\nCache-Control: no-cache\r\nServer: Tengine\r\nConnection: close\r\nPragma: no-cache\r\nExpires: -1\r\nContent-Length: 0\r\nLocation: %s\r\n\r\n"
#define COMMONHEADER_1_COOKIE   "HTTP/1.1 302 Found\r\nCache-Control: no-cache\r\nServer: Tengine\r\nConnection: close\r\nPragma: no-cache\r\nExpires: -1\r\nContent-Length: 0\r\nLocation: %s\r\nSet-Cookie: %s;Domain=%s;Path=/;Max-Age=%d\r\n\r\n"

#define COMMONHEADER_2          "HTTP/1.1 200 OK\r\nCache-Control: no-cache\r\nServer: Tengine\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nPragma: no-cache\r\nExpires: -1\r\nContent-Length: %d\r\n\r\n"
#define COMMONHEADER_2_COOKIE   "HTTP/1.1 200 OK\r\nCache-Control: no-cache\r\nServer: Tengine\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nPragma: no-cache\r\nExpires: -1\r\nContent-Length: %d\r\n%s\r\n\r\n"

#define COMMONHEADER_3          "HTTP/1.1 200 OK\r\nServer: Tengine\r\nContent-Type: application/x-javascript;\r\nVary: Accept-Encoding\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nConnection: close\r\nExpires: -1\r\nContent-Length: %d\r\n\r\n"
#define COMMONHEADER_3_COOKIE   "HTTP/1.1 200 OK\r\nServer: Tengine\r\nContent-Type: application/x-javascript;\r\nVary: Accept-Encoding\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nConnection: close\r\nExpires: -1\r\nContent-Length: %d\r\n%s\r\n\r\n"

#define COMMONHEADER_10 "HTTP/1.1 302 Found\r\nServer: Tengine\r\nConnection: close\r\nLocation: http://www.163.com\r\n\r\n"

#define HEADER_COOKIE   "Set-Cookie: %s;Domain=%s;Path=/;Max-Age=%d\r\n"


#define BIT_SET(a,b) ((a) |= (1<<(b)))
#define BIT_CLEAR(a,b) ((a) &= ~(1<<(b)))
#define BIT_FLIP(a,b) ((a) ^= (1<<(b)))
#define BIT_CHECK(a,b) ((a) & (1<<(b)))

#define BIT_GET(a,b) ((a & (1 << b)) >> b)

#define MAX_CAP                         1600
//#define MAX_CAP                         10000


//extern pcap_t * ghSniff;

//#define MAX_FILE_TYPE_LEN       16
//char gFilterFileType[][MAX_FILE_TYPE_LEN] = {".png", ".jpg", ".css", ".gif", ".jpeg", ".bmp", ".webp", ".xml", ".mp4", ".mp3", ".JPEG"};
extern std::vector<std::string> gFilterFileType;

extern CSystemData g_systemData;
extern CDomainRuleNode g_domainRuleNode;
extern ThreadPool *g_pPool;
extern SYS_RUNTIME_INFO gSysRuntimeInfo[];
extern int g_systemExit;
extern int gDebugLv;
extern u_char g_routermac[];
extern u_char g_sendermac[];
extern int g_dns_location_server[4];

#ifdef USE_SPINLOCK
extern pthread_spinlock_t g_packet_proc_thread_spinlock;
#else
extern pthread_mutex_t g_packet_proc_thread_mutex;
#endif
extern pthread_mutex_t g_send_packet_mutex[];

extern u_char *dns_label_to_str(u_char **label, u_char *dest,
                               size_t dest_size,
                               const u_char *payload,
                               const u_char *end);

extern u_char *skip_dns_label(u_char *label);

extern uint16_t udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr);

struct  timeval  g_timePoint[20][8][10][2];
#define P_START(KEY, nc_id, thread_id)    gettimeofday(&g_timePoint[KEY][nc_id][thread_id][0],NULL);
#define P_END(KEY, nc_id, thread_id)      gettimeofday(&g_timePoint[KEY][nc_id][thread_id][1],NULL);
unsigned long g_splitSize[3] = {0};

unsigned long long g_ipPacketCount[MAX_SNIFFER_THREAD_COUNT] = {0};
unsigned long long g_httpPacketCount[MAX_SNIFFER_THREAD_COUNT] = {0};
unsigned long long temp_count[3]={0};

void Printf_TimePointResult(int nc_index, int thread_index)
{
    unsigned long long timer = 0;

    //for (int i = 0; i < 1; i++)
    //{
        //for (int j = 0; j < g_systemData.m_totalThreadCount; j++) 
        //{
                printf("~~~~~~ NC [%d] Thrd [%d]        ~~~~~~\n", nc_index, thread_index);
            for (int k = 0; k < 9; k++) 
            {
                //timer = 1000000 * (end.tv_sec-start.tv_sec)+ end.tv_usec-start.tv_usec;
                timer = 1000000 * (g_timePoint[k][nc_index][thread_index][1].tv_sec-g_timePoint[k][nc_index][thread_index][0].tv_sec)+ g_timePoint[k][nc_index][thread_index][1].tv_usec-g_timePoint[k][nc_index][thread_index][0].tv_usec;
                printf("~~~~~~ Step [%d]  Time [%8d] us ~~~~~~\n", k, timer);

                g_timePoint[k][nc_index][thread_index][1].tv_sec = 0;
                g_timePoint[k][nc_index][thread_index][0].tv_sec = 0;
                g_timePoint[k][nc_index][thread_index][1].tv_usec = 0;
                g_timePoint[k][nc_index][thread_index][0].tv_usec = 0;
            }
        //}
    //}

    for (int i = 0; i < 3; i++) 
    {
        printf("~~~~~~ g_splitSize [%d]  ~~~~~~\n", g_splitSize[i]);
    }
}


string& replace_all(string& str,const string& old_value,const string& new_value)
{
    while(true)
    {
        int pos=0;
        if((pos=str.find(old_value,0))!=string::npos)
        {
            str.replace(pos,old_value.length(),new_value);
        }
        else
        {
            break;
        }
    }
    return str;
}

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register int sum=0;
	u_short oddbyte;
        
	while(nbytes>1){
        	sum+=*ptr++;
	        nbytes-=2;    
	}
	if(nbytes==1){
        	oddbyte=0;
	        *(u_char *)(&oddbyte)=*(u_char *)ptr;
        	sum+=oddbyte;
	}               
	sum = (sum >> 16) + (sum & 0xFFFF);
	return ~(sum  + (sum >> 16)) & 0xFFFF;
}

unsigned short ip_in_cksum(struct iphdr *iph, unsigned short *ptr, int nbytes)
{
	register int sum = 0;
	u_short oddbyte;
	int pheader_len;
	unsigned short *pheader_ptr;
	
	struct pseudo_header {
		unsigned int saddr;
		unsigned int daddr;
		unsigned char null;
		unsigned char proto;
		unsigned short tlen;
	} pheader;
	
	pheader.saddr = iph->saddr;
	pheader.daddr = iph->daddr;
	pheader.null = 0;
	pheader.proto = iph->protocol;
	pheader.tlen = htons(nbytes);
	
	pheader_ptr = (unsigned short *)&pheader;
	for (pheader_len = sizeof(pheader); pheader_len; pheader_len -= 2) {
		sum += *pheader_ptr++;
	}
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*(u_char *) (& oddbyte) = *(u_char *) ptr;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	return ~(sum  + (sum >> 16)) & 0xFFFF;
}

//! \brief
//!     Calculate the UDP checksum (calculated with the whole
//!     packet).
//! \param buff The UDP packet.
//! \param len The UDP packet length.
//! \param src_addr The IP source address (in network format).
//! \param dest_addr The IP destination address (in network format).
//! \return The result of the checksum.
uint16_t udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
{
        const uint16_t *buf = (const uint16_t *)buff;
        uint16_t *ip_src=(uint16_t *)&src_addr, *ip_dst=(uint16_t *)&dest_addr;
        uint32_t sum;
        size_t length=len;

        // Calculate the sum                                            //
        sum = 0;
        while (len > 1)
        {
                sum += *buf++;
                if (sum & 0x80000000)
                        sum = (sum & 0xFFFF) + (sum >> 16);
                len -= 2;
        }

        if ( len & 1 )
                // Add the padding if the packet lenght is odd          //
                sum += *((uint8_t *)buf);

        // Add the pseudo-header                                        //
        sum += *(ip_src++);
        sum += *ip_src;

        sum += *(ip_dst++);
        sum += *ip_dst;

        sum += htons(IPPROTO_UDP);
        sum += htons(length);

        // Add the carries                                              //
        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        // Return the one's complement of sum                           //
        return ( (uint16_t)(~sum)  );
}

void ProcessHost4Cookie(std::string &host)
{
    /*
    if (host.empty())
    {
        return;
    }

    host = replace_all(host, "www.", ""); 

    if (std::count(host.begin(), host.end(), '.') == 3 && host[0] >= '0' && host[0] <= '9')
    {
        return;
    }
    else
    {
        host = "." + host;
    } 
    */ 

    return;
}

int CPacketProcess::analyzeHTTP(int nc_index, int thread_index, int this_type_thread_index, int this_type_thread_conut, ThreadProcessType this_thread_type, const u_char * packet, HttpRequest &httpReq, const CDeviceData* deviceData)
{
#if 0
    struct ether_header *pEther = (struct ether_header *)packet;

    if (ntohs(pEther->ether_type) != ETHERTYPE_IP) 
    {
        return;
    }

	struct iphdr * pIpHdr = (struct iphdr *)(packet+14);
    //struct iphdr * pIpHdr=(void*)(packet+18); //ha tie
    //struct iphdr * pIpHdr=(void*)(packet+30); //liao ning

    if (pIpHdr->protocol != IPPROTO_TCP)
    {
        return;
    }

    struct tcphdr * pTcpHdr=(struct tcphdr *)((char*)(pIpHdr)+((pIpHdr->ihl)<<2));
	u_char *pData=(u_char *)((char*)pTcpHdr+(pTcpHdr->doff<<2));
#else

            ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //if (this_thread_type == ThreadProcess_Fuzzy_WithHost)
    //{
    //    return -9; 
    //}



    P_START(0,nc_index,thread_index);

    struct ether_header *pEther = (struct ether_header*)packet;
	if (pEther->ether_type != htons(ETHERTYPE_IP))
	{
		return -1;
	}

	struct iphdr* pIpHdr = (struct iphdr*)(packet + 14);
	if (pIpHdr->protocol != IPPROTO_TCP)
	{
        if (this_thread_type == ThreadProcess_Exact && pIpHdr->protocol == IPPROTO_UDP)
        {
            struct ether_header *pSndEthHdr = (struct ether_header*)gSysRuntimeInfo[nc_index].sendBuffer[thread_index];
            struct iphdr *pSndIpHdr = (struct iphdr*)(pSndEthHdr + 1);
            struct udphdr *pSndUdpHdr = (struct udphdr*)(((u_char*)pSndIpHdr) + (pSndIpHdr->ihl << 2));
            char * pSendData = (char*)(pSndUdpHdr + 1);

            u_int sendDataLength = 0;
            UdpProcess(pIpHdr, pSendData, &sendDataLength);

            if (sendDataLength == 0)
            {
                return -21;
            }

            RUN_PRINTF("DNS sendDataLength=%d\n", sendDataLength);

            struct udphdr *pUdpHdr = (struct udphdr*)(((u_char*)pIpHdr) + (pIpHdr->ihl << 2));
            pSndUdpHdr->source = pUdpHdr->dest;
            pSndUdpHdr->dest = pUdpHdr->source;
            pSndUdpHdr->len = ntohs(sendDataLength + 8);
            pSndUdpHdr->check = 0;

            pSndIpHdr->version = 4;
            pSndIpHdr->ihl = 5;
        	pSndIpHdr->ttl = 64;
            pSndIpHdr->protocol = IPPROTO_UDP;
            pSndIpHdr->tos = 0;
            pSndIpHdr->tot_len = ntohs(sendDataLength + 8 + 20);
            pSndIpHdr->id = 0;
            pSndIpHdr->frag_off = 0;
            pSndIpHdr->check = 0;
            pSndIpHdr->saddr = pIpHdr->daddr;
            pSndIpHdr->daddr = pIpHdr->saddr;

            memcpy(pSndEthHdr->ether_dhost, g_routermac, ETH_ALEN);
            memcpy(pSndEthHdr->ether_shost, pEther->ether_dhost, ETH_ALEN);
            pSndEthHdr->ether_type = htons(ETHERTYPE_IP);

            //pSndUdpHdr->check = udp_checksum((void*)pUdpHdr, ntohs(pUdpHdr->len), pSndIpHdr->saddr, pSndIpHdr->daddr);
            pSndUdpHdr->check = ip_in_cksum(pSndIpHdr, (unsigned short*)pSndUdpHdr, sizeof(struct udphdr) + sendDataLength);
            pSndIpHdr->check = in_cksum((unsigned short*)pSndIpHdr, 20);

            int rc = 0;

            #ifdef USE_SPINLOCK
                        pthread_spin_lock(&g_packet_proc_thread_spinlock);
            #else
                        pthread_mutex_lock(&g_packet_proc_thread_mutex);
            #endif

                int totalLen = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sendDataLength;

                if (totalLen > 1500)
                {
                    RUN_PRINTF("Error: totalLen > 1500. totalLen=%d\n", totalLen);
                }

            	rc = pcap_sendpacket(gSysRuntimeInfo[nc_index].ghSender[thread_index], gSysRuntimeInfo[nc_index].sendBuffer[thread_index], totalLen);

                if (rc != 0)
                {
                    RUN_PRINTF("pcap_sendpacket failed, err=%d info=%s\n", rc, pcap_geterr(gSysRuntimeInfo[nc_index].ghSender[thread_index]));
                }

            #ifdef USE_SPINLOCK
                        pthread_spin_unlock(&g_packet_proc_thread_spinlock);
            #else
                        pthread_mutex_unlock(&g_packet_proc_thread_mutex);
            #endif

            return -20;
        }

		return -2;
	}

#define IP_TTL_MIN				5 
    /*ttl 小于特定值 不做处理*/
	if(pIpHdr->ttl <= IP_TTL_MIN)
	{
		DEBUG_PRINTF("ttl < 5 line = %d, fun = %s, file = %s\n", __LINE__, __func__, __FILE__);
		return RETURN_OK;
	}

    #if 1
    if (pIpHdr->id % this_type_thread_conut != this_type_thread_index)
    {
        ///printf("pIpHdr->id=%d, this_type_thread_conut=%d, this_type_thread_index=%d\n", pIpHdr->id, this_type_thread_conut, this_type_thread_index);
        return -3;
    }
    #endif

    //如果IP属于屏蔽用户IP，直接返回
    if (g_systemData.m_Ip2UserBlacklist.find(pIpHdr->saddr) != g_systemData.m_Ip2UserBlacklist.end())
    {
        char temp[64];
        DEBUG_PRINTF("IP=%s is in the blacklist.\n", IpIntToStr(pIpHdr->saddr, temp));
        return RETURN_OK;
    }

	struct tcphdr * pTcpHdr = (struct tcphdr*)(((u_char*)pIpHdr) + (pIpHdr->ihl << 2));

	//if (pTcpHdr->th_dport != 80)
	//{
	//	return;
	//}

	int len = pTcpHdr->doff;
	char *pData = ((char*)pTcpHdr) + (len << 2);
#endif

    int n;
    if (memcmp(pData,"GET",3) == 0)
    {
        //DEBUG_PRINTF("analyzeHTTP: [nc_index=%d, thread_index=%d]\n%s\n", nc_index, thread_index, pData);
        
        P_END(0,nc_index,thread_index);
        P_START(1,nc_index,thread_index);

        httpReq.Init();

        int ret = httpReq.ParseData((char*)pData, thread_index);
		if (ret != 0)
		{
			//RUN_PRINTF("httpReq.ParseData() failed, return = %d\n", ret);
            //RUN_PRINTF("pData = %s\n", pData);
            P_END(1,nc_index,thread_index);
			return -4;
		}

        g_httpPacketCount[thread_index]++;

        int err = MatchRulesAndDoAction(nc_index, thread_index, this_thread_type, pEther, pIpHdr, pTcpHdr, httpReq, deviceData);
        if (err != 0)
        {
            return err;
        }
    }

    return 0;
}

unsigned long long CalcIpPacketCount()
{
    unsigned long long total = 0;
    for (int i = 0; i < g_systemData.m_totalThreadCount; i++)
    {
        //total
    }
}

//u_char data_buf_cpy[10][32][MAX_CAP+1];

void CPacketProcess::PacketProcess(int thread_index, int this_type_thread_index, int this_type_thread_conut, ThreadProcessType this_thread_type, const CDeviceData* deviceData)
{
    const u_char 	    * data_buf = NULL;	
    struct pcap_pkthdr  * pcap_info = NULL;

    int err = StartPcap(thread_index, deviceData);
    if (err != 0)
    {
        RUN_PRINTF("StartPcap failed, err=%d\n", err);
        exit(-2);
    }

    HttpRequest* pHttpRequest = new HttpRequest();
    pHttpRequest->Init();

	//struct timespec             start, end;
	//struct pcap_stat	    	stat;

    try
    {
        while (g_systemExit == 0)
        {
#ifdef USE_SPINLOCK
//            pthread_spin_lock(&g_packet_proc_thread_spinlock);
#else
//            pthread_mutex_lock(&g_packet_proc_thread_mutex);
#endif

            int err = pcap_next_ex(gSysRuntimeInfo[deviceData->m_ID].ghSniff[thread_index], &pcap_info, &data_buf);

            #if 0
            if (pcap_info->caplen <= MAX_CAP+1) 
            {
                memcpy(data_buf_cpy[deviceData.m_ID][thread_index], data_buf, pcap_info->caplen);
            }
            else
            {
                printf("Error: caplen [%d] > MAX_CAP\n", pcap_info->caplen);
            }
            #endif

            g_ipPacketCount[thread_index]++;

            ((CDeviceData*)deviceData)->m_snifferNetworkCard.m_statInfo.totalPacketCount++;

#ifdef USE_SPINLOCK
//            pthread_spin_unlock(&g_packet_proc_thread_spinlock);
#else
//            pthread_mutex_unlock(&g_packet_proc_thread_mutex);
#endif

            //if (err >= 0)
            if (err == 1)
            {
                struct  timeval  start;
                struct  timeval  end;
                unsigned long timer;
                gettimeofday(&start,NULL);

                int ret = analyzeHTTP(deviceData->m_ID, thread_index, this_type_thread_index, this_type_thread_conut, this_thread_type, data_buf/*_cpy[deviceData.m_ID][thread_index]*/, *pHttpRequest, deviceData);
                //memset((void*)data_buf_cpy[deviceData.m_ID][thread_index], 0x00, pcap_info->caplen);

                gettimeofday(&end,NULL);
                timer = 1000000 * (end.tv_sec-start.tv_sec)+ end.tv_usec-start.tv_usec;
                if (timer > 30000)
                {
                    printf("Leo test: analyzeHTTP timer = %ld us [%d-%d]\n [%s]\n", timer, deviceData->m_ID, thread_index, pHttpRequest->url.c_str());

                    if (ret == 0 && pHttpRequest->url.empty())
                    {
                        printf("[Host:%s], [Path:%s]\n", pHttpRequest->Host.c_str(), pHttpRequest->Path.c_str());
                    }

                    Printf_TimePointResult(deviceData->m_ID, thread_index);
                    //cout << httpRequest.ToString();
                }

//              if (pHttpRequest->url.compare("www.kaichi-bendi.cn/") == 0)
//              {
//                  printf("Leo test: analyzeHTTP timer = %ld us\n [%s]\n", timer, pHttpRequest->url.c_str());
//                  printf("PacketProcess nc_inx %d, thd %d count %d err=%d\n", deviceData->m_ID, thread_index, g_ipPacketCount[thread_index], err);
//                  printf("ip_count=%d, err0=%d, err-1=%d, err-2=%d\n", g_ipPacketCount[thread_index], temp_count[0], temp_count[1], temp_count[2]);
//                  cout << pHttpRequest->ToString();
//              }
            }
            else
            {
                //RUN_PRINTF("pcap_next_ex failed, return =%d\n", err);
                if (err==0) 
                {
                    temp_count[0]++;
                }
                else if (err == -1) 
                {
                    temp_count[1]++;
                }
                else if (err == -2)
                {
                    temp_count[2]++;
                }
            }
        }

    }
    catch (std::exception& e)
    {
        cout << "some unhappy happened... " << std::this_thread::get_id() << e.what() << endl;
    }

    delete pHttpRequest;
    pHttpRequest = NULL;

    return; 
}

/**
 * 启动监听
 * */
int CPacketProcess::StartSnifferPacket(const CDeviceData* deviceData)
{    
    g_systemData.m_totalThreadCount = g_systemData.m_snifferThreadCount + g_systemData.m_fuzzy_with_host_thread_count + g_systemData.m_fuzzy_without_host_thread_count;
    for (int x = 0; x < g_systemData.m_totalThreadCount; x++) 
    {
        memset(gSysRuntimeInfo[deviceData->m_ID].sendBuffer[x], 0, 10240);
    }

    int thread_index = 0;
    for (int i = 0; i < g_systemData.m_snifferThreadCount; i++)
    {
        g_pPool->enqueue(CPacketProcess::PacketProcess, thread_index, i, g_systemData.m_snifferThreadCount, ThreadProcess_Exact, deviceData);
        thread_index++;
    }

    for (int i = 0; i < g_systemData.m_fuzzy_with_host_thread_count; i++)
    {
        g_pPool->enqueue(CPacketProcess::PacketProcess, thread_index, i, g_systemData.m_fuzzy_with_host_thread_count, ThreadProcess_Fuzzy_WithHost, deviceData);
        thread_index++;
    }

    for (int i = 0; i < g_systemData.m_fuzzy_without_host_thread_count; i++)
    {
        g_pPool->enqueue(CPacketProcess::PacketProcess, thread_index, i, g_systemData.m_fuzzy_without_host_thread_count, ThreadProcess_Fuzzy_WithOutHost, deviceData);
        thread_index++;
    }

    /*
    while (g_systemExit == 0)
    {
        sleep(60);
    } 
    */ 

    return 0;
}

int CPacketProcess::StartPcap(int thread_index, const CDeviceData* deviceData)
{
    RUN_PRINTF("Start Sniffer Thread.      [NC_name = %s, NC_ID = %d\n"
           , deviceData->m_snifferNetworkCard.m_name.c_str(), deviceData->m_ID);

    /*
    //memcached init
    memcached_return rc;
    int user_port_num = 11200 + deviceData.m_ID;
    memcached_server_st *servers_user =  memcached_server_list_append(NULL,"127.0.0.1",user_port_num,&rc);
    const char *config_string = "--POOL-MIN=5 --POOL-MAX=100";
    gSysRuntimeInfo[deviceData.m_ID].ghMem_user = memcached(config_string, strlen(config_string));
    memcached_server_push(gSysRuntimeInfo[deviceData.m_ID].ghMem_user, servers_user);
    memcached_server_list_free(servers_user);

    memcached_behavior_set(gSysRuntimeInfo[deviceData.m_ID].ghMem_user, MEMCACHED_BEHAVIOR_BUFFER_REQUESTS, 0);
    //memcached_behavior_set(ghMem, MEMCACHED_BEHAVIOR_NOREPLY, 1);
    memcached_behavior_set(gSysRuntimeInfo[deviceData.m_ID].ghMem_user, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
    memcached_behavior_set(gSysRuntimeInfo[deviceData.m_ID].ghMem_user, MEMCACHED_BEHAVIOR_HASH, MEMCACHED_HASH_DEFAULT);        
    memcached_behavior_set(gSysRuntimeInfo[deviceData.m_ID].ghMem_user, MEMCACHED_BEHAVIOR_NO_BLOCK, 1); 
    memcached_behavior_set(gSysRuntimeInfo[deviceData.m_ID].ghMem_user, MEMCACHED_BEHAVIOR_TCP_NODELAY, 1); 
    //memcached init end. 
    */ 

    char aErrBuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;

    if(gSysRuntimeInfo[deviceData->m_ID].ghSniff[thread_index])
    {
        pcap_close(gSysRuntimeInfo[deviceData->m_ID].ghSniff[thread_index]);
    }

#if 1
    gSysRuntimeInfo[deviceData->m_ID].ghSniff[thread_index] = pcap_open_live(deviceData->m_snifferNetworkCard.m_name.c_str(), MAX_CAP, 1, 50, aErrBuf);

    if(gSysRuntimeInfo[deviceData->m_ID].ghSniff[thread_index] == NULL)
    {
        RUN_PRINTF("pcap_open_live():%s\n",aErrBuf);
        exit(-1);
    }
    RUN_PRINTF("open device successful.    [NC_name = %s, ThreadIndex = %d]\n", deviceData->m_snifferNetworkCard.m_name.c_str(), thread_index);

#else

    gSysRuntimeInfo[deviceData.m_ID].ghSniff[thread_index] = pcap_create(deviceData.m_snifferNetworkCard.m_name.c_str(), aErrBuf);

    if(gSysRuntimeInfo[deviceData.m_ID].ghSniff[thread_index] == NULL)
    {
        RUN_PRINTF("pcap_create():%s\n",aErrBuf);
        exit(-1);
    }
    RUN_PRINTF("open device successful\n");

    pcap_set_snaplen(gSysRuntimeInfo[deviceData.m_ID].ghSniff[thread_index], MAX_CAP);
    pcap_set_promisc(gSysRuntimeInfo[deviceData.m_ID].ghSniff[thread_index], 1);
    pcap_set_timeout(gSysRuntimeInfo[deviceData.m_ID].ghSniff[thread_index], 50);

    //734003200 - 700MB 1572864000-1500MB
    int err = pcap_set_buffer_size(gSysRuntimeInfo[deviceData.m_ID].ghSniff[thread_index], 134003200);
    if (err != 0) 
    {
        RUN_PRINTF("pcap_set_buffer_size(): err=%d\n",err);
        exit(-1);
    }

    err = pcap_activate(gSysRuntimeInfo[deviceData.m_ID].ghSniff[thread_index]);
    if (err != 0) 
    {
        RUN_PRINTF("pcap_activate(): err=%d\n",err);
        exit(-1);
    }

#endif

    u_int net_mask = 0xffffff;
    //if(pcap_compile(gSysRuntimeInfo[deviceData.m_ID].ghSniff[thread_index], &filter, "ip and ip[6:1]&2=0 and tcp and greater 80 and tcp[tcpflags]&(tcp-syn|tcp-fin)=0 and port 80", 1, PCAP_NETMASK_UNKNOWN) == -1)
    //if(pcap_compile(gSysRuntimeInfo[deviceData.m_ID].ghSniff[thread_index], &filter, "tcp[20:2]=0x4745 or tcp[20:2]=0x504F", 1, net_mask) == -1) 
    int err = pcap_compile(gSysRuntimeInfo[deviceData->m_ID].ghSniff[thread_index], &filter, "tcp[20:2]=0x4745 or udp", 1, net_mask);
    if(err == -1)
    {
		RUN_PRINTF("Error on pcap_compile [%d-%d] err:%s\n", deviceData->m_ID, thread_index, pcap_statustostr(err));
		exit(-1);
	}
	RUN_PRINTF("compile successful\n");

	if(pcap_setfilter(gSysRuntimeInfo[deviceData->m_ID].ghSniff[thread_index], &filter) == -1)
	{
		RUN_PRINTF("Error no pcap_setfilter\n");
		exit(-1);
	}
	RUN_PRINTF("setfilter successful\n");

    if (deviceData->m_snifferNetworkCard.m_name.compare(deviceData->m_sendNetworkCard.m_name) == 0)
    {
        gSysRuntimeInfo[deviceData->m_ID].ghSender[thread_index] = gSysRuntimeInfo[deviceData->m_ID].ghSniff[thread_index];
        DEBUG_PRINTF("ghSender = ghSniff\n");

        /*
        if(pcap_setdirection(gSysRuntimeInfo[deviceData.m_ID].ghSniff, PCAP_D_IN) == -1)
        {
            RUN_PRINTF("No Support on set direction");
        }
        DEBUG_PRINTF("pcap_setdirection\n"); 
        */  
    }
    else
    {
        if(gSysRuntimeInfo[deviceData->m_ID].ghSender[thread_index])
        {
            pcap_close(gSysRuntimeInfo[deviceData->m_ID].ghSender[thread_index]);
        }
        
        gSysRuntimeInfo[deviceData->m_ID].ghSender[thread_index] = pcap_open_live(deviceData->m_sendNetworkCard.m_name.c_str(),1,1,-1,aErrBuf);

        if(gSysRuntimeInfo[deviceData->m_ID].ghSender[thread_index] == NULL)
        {
            RUN_PRINTF("pcap_open_live() failed:%s\n",aErrBuf);
            exit(-1);
        }

        //if(pcap_compile(gSysRuntimeInfo[deviceData.m_ID].ghSender[thread_index], &filter,"not ip",1,PCAP_NETMASK_UNKNOWN)==-1)
        //{
        //    RUN_PRINTF("Error on pcap_compile\n");
        //    exit(-1);
        //}
    }

    RUN_PRINTF("httpSniff init successful. [NC_name = %s, ThreadIndex = %d]\n", deviceData->m_snifferNetworkCard.m_name.c_str(), thread_index);

    return 0;
}

int CPacketProcess::MatchRulesAndDoAction(int nc_index, int thread_index, ThreadProcessType this_thread_type, struct ether_header *pEther, struct iphdr * pIpHdr, struct tcphdr * pTcpHdr,
									const HttpRequest &request, const CDeviceData* deviceData)
{
    bool bExactMatch = false;
    bool bFuzzyNoHostMatch = false;
    bool bFuzzyWithHostMatch = false;
    int num = 0;
	string pointid = "";
    vector<CData>::iterator it;
    unordered_map<string, CData>::iterator exactIt;     //exactDataMap
    unordered_map<string, vector<CData>>::iterator fuzzyWithHostIt;

	//num
	num = g_domainRuleNode.num;

	//pointid
	pointid = g_domainRuleNode.pointid;

    P_END(1,nc_index,thread_index);

    if (this_thread_type == ThreadProcess_Exact)
    {
        P_START(2,nc_index,thread_index);
        //url精确匹配
        exactIt = g_domainRuleNode.exactDataMap.find(request.url);

        if (exactIt != g_domainRuleNode.exactDataMap.end())
        {
            //url精确匹配成功
            //exactIt->second.count++;
            bExactMatch = true;
            P_END(2,nc_index,thread_index);
        }
        else
        {
            P_END(2,nc_index,thread_index);
            return -1;
        }
        P_END(2,nc_index,thread_index);
    }
    else if (this_thread_type == ThreadProcess_Fuzzy_WithHost) 
    {
        P_START(2,nc_index,thread_index);
        //模糊匹配&有Host规则
        exactIt = g_domainRuleNode.exactDataMap.find(request.url);

        if (exactIt != g_domainRuleNode.exactDataMap.end())
        {
            //url精确匹配成功,本线程不处理
            P_END(2,nc_index,thread_index);
            return -2;
        }

        unordered_map<string, vector<CData>>::iterator fuzzyWithHostIt = g_domainRuleNode.fuzzy_WithHost_DataMap.find(request.Host);

        if (fuzzyWithHostIt != g_domainRuleNode.fuzzy_WithHost_DataMap.end()) 
        {
            //模糊匹配&有Host规则

            //检查url过滤文件名
            int err = CheckFileTypeFilter(request);
            if (err != 0)
            {
                P_END(2,nc_index,thread_index);
                return -9;
            }

            //data	
        	for (it = fuzzyWithHostIt->second.begin(); it != fuzzyWithHostIt->second.end(); ++it)
        	{
        		string objectid = "";
        		string exact = "";
        		string fuzzy = "";
                string urlaccord = "";
        		string urlfilter = "";
        		string agentfilter = "";
        		string agentmatch = "";
                string ratekey = "";

        		bool isrefer = false;
        		int pushrate = 0;

                CData &data_element = *it;

        		objectid = data_element.objectid;
        		exact = data_element.exact;
        		fuzzy = data_element.fuzzy;
                urlaccord = data_element.urlaccord;
        		urlfilter = data_element.urlfilter;
        		//agentfilter = data_element.agentfilter;
        		//agentmatch = data_element.agentmatch;
        		//isrefer = data_element.isrefer;
        		pushrate = data_element.pushrate;
                ratekey = data_element.ratekey;

                //DEBUG_PRINTF("objectid=%s, exact=%s, fuzzy=%s, urlaccord=%s, urlfilter=%s, pushrate=%d, ratekey=%s\n"
                //             ,objectid.c_str(), exact.c_str(), fuzzy.c_str(), urlaccord.c_str(), urlfilter.c_str(), pushrate, ratekey.c_str());

                //DEBUG_PRINTF("request.url = %s\n", request.url.c_str());            


                if (!fuzzy.empty())
        		{
                    int res = fnmatch(fuzzy.c_str(), request.url.c_str(), 0);
                    if (res == 0)
                    {
                        /*
                        if (!data_element.urlaccord.empty())
                        {
                            for (vector<string>::iterator it2 = data_element.urlaccordSet.begin(); it2 != data_element.urlaccordSet.end(); ++it2)
                            {
                                if (request.url.find(*it2) == std::string::npos)
                                {
                                    return -3;
                                }
                            }
                        } 
                        */ 

                        if (!data_element.urlfilter.empty())
                        {
                            for (vector<string>::iterator it2 = data_element.urlfilterSet.begin(); it2 != data_element.urlfilterSet.end(); ++it2)
                            {
                                if (request.url.find(*it2) != std::string::npos)
                                {
                                    P_END(2,nc_index,thread_index);
                                    return -4;
                                }
                            }
                        }

                        //it->count++;
                        bFuzzyWithHostMatch = true;
                        break;
                    }
                    else
                    {
                        continue;
                    }

        			////正则表达式判断
                    /*			
        			try
        			{
        				boost::regex reg(fuzzy);
        				bool match = boost::regex_match(request.url, reg);
        				if (!match)
        				{
        					continue;
        				}
        			}
        			catch (const exception& e)
        			{
        				LOG4CXX_ERROR(logger, e.what());
        			}
                    */
        		}
                else
                {
                    continue;
                }

                /*
        		if (!agentfilter.empty())
        		{
        			if (request.UserAgent.find(agentfilter) != std::string::npos)
        			{
        				continue;
        			}
        		}

        		if (!agentmatch.empty())
        		{
        			if (request.url.find(agentmatch) == std::string::npos)
        			{
        				continue;
        			}
        		}

        		if (isrefer && request.Referer.empty())
        		{
        			continue;
                } 
                */	
            }

            if (it == fuzzyWithHostIt->second.end())
            {
                //url模糊匹配&有Host匹配不满足
                P_END(2,nc_index,thread_index);
                //goto FUZZY_NO_HOST_RULE_MATCH;
                return -3;
            }
            P_END(2,nc_index,thread_index);
        }
        else
        {
            P_END(2,nc_index,thread_index);
            return -3;
        }
    }
    else
    {
        //模糊匹配&无Host
        P_START(2,nc_index,thread_index);
        
        exactIt = g_domainRuleNode.exactDataMap.find(request.url);

        if (exactIt != g_domainRuleNode.exactDataMap.end())
        {
            //url精确匹配成功,本线程不处理
            P_END(2,nc_index,thread_index);
            return -2;
        }

        //unordered_map<string, vector<CData>>::iterator fuzzyWithHostIt = g_domainRuleNode.fuzzy_WithHost_DataMap.find(request.Host);

        //if (fuzzyWithHostIt != g_domainRuleNode.fuzzy_WithHost_DataMap.end()) 
        //{
            //模糊匹配&有Host规则,本线程不处理
        //    return -3;
        //}

        //模糊匹配&无Host规则
        
        //检查url过滤文件名
        int err = CheckFileTypeFilter(request);
        if (err != 0)
        {
            P_END(2,nc_index,thread_index);
            return -9;
        }

        std::vector<CData> fuzzy_NoHost_Rules;
        err = GetRulesByDictionary(request, fuzzy_NoHost_Rules, it);

        if (err != 0)
        {
            P_END(2,nc_index,thread_index);
            return err;
        }

        bFuzzyNoHostMatch = true;

        P_END(2,nc_index,thread_index);
    }

    P_START(3,nc_index,thread_index);

    CData* pData_element = NULL;    

    if (bExactMatch)
    {
        pData_element = &(exactIt->second);
    }
    else if (bFuzzyNoHostMatch)
    {
        pData_element = &(*it);
    }
    else
    {
        pData_element = &(*it);
    }

    if (pData_element == NULL)
    {
        //printf("pData_element == NULL");
        P_END(3,nc_index,thread_index);
        return -1;
    }

    string objectid = pData_element->objectid;

    //pData_element->pushrate = 1;
    //pData_element->ratekey = "test";

    if (pData_element->pushrate > 0)
    {
        /*
        DWORD tick = GetTickCount();
        if ((tick - data_element.lastTick) / 1000 < pushrate)
        {
            continue;
        }
        */
        std::string rule;
        if (!pData_element->exact.empty())
        {
            rule = pData_element->exact;
        }
        else
        {
            rule = pData_element->fuzzy;
        }

        if (CheckPushRate(nc_index, thread_index, pData_element->pushrate, pData_element->ratekey, rule, pIpHdr->saddr, request.UserAgent, request.Cookie) != 0)
        {
            P_END(3,nc_index,thread_index);
            return -5;
        }

        //printf("Rule: %s\n", rule.c_str());
    }

    pData_element->count++;
    //data_element.lastTick = GetTickCount();

    P_END(3,nc_index,thread_index);
    P_START(4,nc_index,thread_index);

    ((CDeviceData *)deviceData)->m_snifferNetworkCard.m_statInfo.matchRulePacketCount++;

    //满足条件，执行随机动作
    int accountNum = pData_element->account.size();
    //DEBUG_PRINTF("accountNum = %d\n", accountNum);
    if (accountNum > 0)
    {
        int actionIndex = ActionRand(0, accountNum); 

        //DEBUG_PRINTF("actionIndex = %d\n", actionIndex);

        if (actionIndex >= 0 && actionIndex < pData_element->account.size())
        {
            string &accountid   = pData_element->account[actionIndex]->accountid;
            string &pushtype    = pData_element->account[actionIndex]->pushtype;
            string &replacekey  = pData_element->account[actionIndex]->replacekey;
            string &pushcontent = pData_element->account[actionIndex]->pushcontent;

            pData_element->account[actionIndex]->pushCount++;

            //替换s%为当前url
            pushcontent = replace_all(pushcontent, "%s", request.url);

            string cookie;
            MakePushCookie(cookie, request.Host, pData_element->pushrate);
            //cout << "cookie = " << cookie << endl;
            //DEBUG_PRINTF("url==[%s]\n", request.url.c_str());
            //动作
            DoAction(nc_index, thread_index, pEther, pIpHdr, pTcpHdr, objectid, accountid, pushtype, replacekey, pushcontent, cookie);
        }
    }

    P_END(4,nc_index,thread_index);

    return RETURN_OK;
}

int CPacketProcess::ActionRand(int min, int max)
{
	return (rand() % (max - min)) + min;
}

void CPacketProcess::DoAction(int nc_index, int thread_index, struct ether_header *pEthSrc, struct iphdr * pIpSrc, struct tcphdr * pTcpSrc,
	const string &objectid, const string &accountid, const string &pushtype, const string &replacekey, const string &pushcontent, 
    const string &cookie)
{
//  char szBuf[256] = {0};
//  time_t timer = time(NULL);
//  strftime(szBuf, sizeof(szBuf), "%Y-%m-%d %H:%M:%S", localtime(&timer));

	if (pushtype.compare("link") == 0)
	{
		inject_302_Location(nc_index, thread_index, pEthSrc, pIpSrc, pTcpSrc, pushcontent, cookie);
		//RUN_PRINTF("inject_302_[%s] = %s\n", szBuf, pushcontent.c_str());
	}
	else if (pushtype.compare("js") == 0)
	{
		inject_200_Content(nc_index, thread_index, pEthSrc, pIpSrc, pTcpSrc, pushcontent, pushtype, cookie);
		//RUN_PRINTF("inject_200_[%s] = %s\n", szBuf, pushcontent.c_str());
	}
	else if (pushtype.compare("html") == 0)
	{
		inject_200_Content(nc_index, thread_index, pEthSrc, pIpSrc, pTcpSrc, pushcontent, pushtype, cookie);
        /*
        if (pushcontent.compare("Succes") == 0 
            || pushcontent.compare("1") == 0 || pushcontent.compare("2") == 0
            || pushcontent.compare("3") == 0 || pushcontent.compare("4") == 0
            || pushcontent.compare("5") == 0 || pushcontent.compare("6") == 0) 
        {
            RUN_PRINTF("[nc_index=%d, thread_index=%d]\ninject_200_Content = %s\n", nc_index, thread_index, pushcontent.c_str());
        } 
        */ 
        //RUN_PRINTF("[nc_index=%d, thread_index=%d]\ninject_200_[%s] = %s\n", nc_index, thread_index, szBuf, pushcontent.c_str());
	}
}

int CPacketProcess::inject_302_Location(int nc_index, int thread_index, struct ether_header *pEthSrc, struct iphdr * pIpSrc, struct tcphdr * pTcpSrc, const string &url,
                                        const string &cookie)
{
	int c;

	struct ether_header *pEth = (struct ether_header*)gSysRuntimeInfo[nc_index].sendBuffer[thread_index];
	struct iphdr *pIp = (struct iphdr*)(pEth + 1);
	struct tcphdr *pTcp = (struct tcphdr*)(pIp + 1);
	char * pData = (char*)(pTcp + 1);
	int DataLen = 0;

	char buf[1024] = {0};

#ifndef USE_COOKIE_FOR_CHECKPUSHRATE
    sprintf(buf, COMMONHEADER_1, url.c_str());
#else
    if (cookie.empty()) 
    {
        sprintf(buf, COMMONHEADER_1, url.c_str());
    }
    else
    {
        sprintf(buf, COMMONHEADER_1_COOKIE, url.c_str(), cookie.c_str());
    }
#endif

	//sprintf(buf, 1024, COMMONHEADER_1, "http://www.163.com/");
	strcpy(pData, buf);
	
	//strcpy_s(pData, 1024, COMMONHEADER_1);

	DataLen = strlen(pData);

	//memcpy(pEth->ether_dhost, pEthSrc->ether_shost, ETH_ALEN);
    memcpy(pEth->ether_dhost, g_routermac, ETH_ALEN);
	memcpy(pEth->ether_shost, pEthSrc->ether_dhost, ETH_ALEN);

    pEth->ether_type = htons(ETHERTYPE_IP);    //From initVars

	//memcpy(pEth->eh_dst, pEthSrc->eh_dst, ETH_ALEN);
	//memcpy(pEth->eh_src, pEthSrc->eh_src, ETH_ALEN);

	//printf("\r\npEth->eh_dst： %2x-%2x-%2x-%2x-%2x-%2x\r\n", pEth->eh_dst[0], pEth->eh_dst[1], pEth->eh_dst[2], pEth->eh_dst[3], pEth->eh_dst[4], pEth->eh_dst[5]);
	//printf("\r\npEth->eh_src： %2x-%2x-%2x-%2x-%2x-%2x\r\n", pEth->eh_src[0], pEth->eh_src[1], pEth->eh_src[2], pEth->eh_src[3], pEth->eh_src[4], pEth->eh_src[5]);

    //From initVars
    pIp->version = 4;
    pIp->ihl = 5;
	pIp->ttl = 64;
	pIp->protocol = IPPROTO_TCP;
    pTcp->doff = 5;
    //From initVars

	pIp->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + DataLen);
	pIp->saddr = pIpSrc->daddr;
	pIp->daddr = pIpSrc->saddr;

	pIp->id = pIpSrc->id;
	pIp->check = 0;
	pIp->check = in_cksum((unsigned short*)pIp, 20);

	pTcp->source = pTcpSrc->dest;
	pTcp->dest = pTcpSrc->source;
	pTcp->seq = pTcpSrc->ack_seq;
	//printf("2: %d\n", pTcp->th_seq);

	pTcp->ack_seq=htonl((pTcpSrc->syn>0)+(pTcpSrc->fin>0)+ntohl(pTcpSrc->seq)+(ntohs(pIpSrc->tot_len)-(pIpSrc->ihl<<2)-(pTcpSrc->doff<<2)));

	pTcp->window = pTcpSrc->window;

	//pTcp->fin = 1;
	pTcp->fin = 1; 
    pTcp->ack = 1;

	pTcp->check = 0;
	pTcp->check = ip_in_cksum(pIp, (unsigned short*)pTcp, sizeof(struct tcphdr) + DataLen);
	int rc = 0;

    //pthread_mutex_lock(&g_send_packet_mutex[0]);
	//rc = pcap_inject(ghSniff, gSendBuf, sizeof(ETHDR) + sizeof(IPHDR) + sizeof(TCPHDR) + DataLen);

#ifdef USE_SPINLOCK
            pthread_spin_lock(&g_packet_proc_thread_spinlock);
#else
            pthread_mutex_lock(&g_packet_proc_thread_mutex);
#endif

    int totalLen = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + DataLen;

    if (totalLen > 1500)
    {
        RUN_PRINTF("Error: totalLen > 1500. totalLen=%d\n", totalLen);
    }

	rc = pcap_sendpacket(gSysRuntimeInfo[nc_index].ghSender[thread_index], gSysRuntimeInfo[nc_index].sendBuffer[thread_index], totalLen);

    if (rc != 0)
    {
        RUN_PRINTF("pcap_sendpacket failed, err=%d info=%s\n", rc, pcap_geterr(gSysRuntimeInfo[nc_index].ghSender[thread_index]));
    }

#ifdef USE_SPINLOCK
            pthread_spin_unlock(&g_packet_proc_thread_spinlock);
#else
            pthread_mutex_unlock(&g_packet_proc_thread_mutex);
#endif

	//printf("pcap_sendpacket return = %d\r\n", rc);
	//printf("th_seq:%d th_ack:%d\r\n", pTcp->th_seq, pTcp->th_ack);

	return 0;
}

int CPacketProcess::inject_200_Content(int nc_index, int thread_index, struct ether_header *pEthSrc, struct iphdr * pIpSrc, struct tcphdr * pTcpSrc, const string &content, const string &pushtype,
                                       const string &cookie)
{
	int c;

	struct ether_header *pEth = (struct ether_header*)gSysRuntimeInfo[nc_index].sendBuffer[thread_index];
	struct iphdr *pIp = (struct iphdr*)(pEth + 1);
	struct tcphdr *pTcp = (struct tcphdr*)(pIp + 1);
	char * pData = (char*)(pTcp + 1);
	int DataLen = 0;

	char buf[9*1024];

	if (pushtype.compare("html") == 0)
	{
#ifndef USE_COOKIE_FOR_CHECKPUSHRATE
        sprintf(buf, COMMONHEADER_2, content.length());
#else
        if (cookie.empty()) 
        {
            sprintf(buf, COMMONHEADER_2, content.length());
        }
        else
        {
            sprintf(buf, COMMONHEADER_2_COOKIE, content.length(), cookie.c_str());
        }
#endif

		int header_len = strlen(buf);
		strcpy(buf + header_len, content.c_str());
	}
	else if (pushtype.compare("js") == 0)
	{
#ifndef USE_COOKIE_FOR_CHECKPUSHRATE
        sprintf(buf, COMMONHEADER_3, content.length());
#else
        if (cookie.empty()) 
        {
            sprintf(buf, COMMONHEADER_3, content.length());
        }
        else
        {
            sprintf(buf, COMMONHEADER_3_COOKIE, content.length(), cookie.c_str());
        }
#endif

		int header_len = strlen(buf);
		strcpy(buf + header_len, content.c_str());
	}
	//sprintf_s(buf, 1024, COMMONHEADER_1, "http://www.163.com/");
	strcpy(pData, buf);

	//strcpy_s(pData, 1024, COMMONHEADER_1);

	DataLen = strlen(pData);

	//memcpy(pEth->eh_dst, pEthSrc->eh_src, ETH_ALEN);
    memcpy(pEth->ether_dhost, g_routermac, ETH_ALEN);
	memcpy(pEth->ether_shost, pEthSrc->ether_dhost, ETH_ALEN);

    pEth->ether_type = htons(ETHERTYPE_IP);    //From initVars

	//printf("\r\npEth->eh_dst： %2x-%2x-%2x-%2x-%2x-%2x\r\n", pEth->eh_dst[0], pEth->eh_dst[1], pEth->eh_dst[2], pEth->eh_dst[3], pEth->eh_dst[4], pEth->eh_dst[5]);
	//printf("\r\npEth->eh_src： %2x-%2x-%2x-%2x-%2x-%2x\r\n", pEth->eh_src[0], pEth->eh_src[1], pEth->eh_src[2], pEth->eh_src[3], pEth->eh_src[4], pEth->eh_src[5]);

    //From initVars
    pIp->version = 4;
    pIp->ihl = 5;
	pIp->ttl = 64;
	pIp->protocol = IPPROTO_TCP;
    pTcp->doff = 5;
    //From initVars

	pIp->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + DataLen);
	pIp->saddr = pIpSrc->daddr;
	pIp->daddr = pIpSrc->saddr;

	pIp->id = pIpSrc->id;
	pIp->check = 0;
	pIp->check = in_cksum((unsigned short*)pIp, 20);

	pTcp->source = pTcpSrc->dest;
	pTcp->dest = pTcpSrc->source;
	pTcp->seq = pTcpSrc->ack_seq;
	//printf("2: %d\n", pTcp->th_seq);

	//pTcp->th_ack = htonl((pTcpSrc->syn>0) + (pTcpSrc->fin>0) + ntohl(pTcpSrc->th_seq) + (ntohs(pIpSrc->ip_len) - (pIpSrc->ip_hl << 2) - (pTcpSrc->th_off << 2)));
	pTcp->ack_seq=htonl((pTcpSrc->syn>0)+(pTcpSrc->fin>0)+ntohl(pTcpSrc->seq)+(ntohs(pIpSrc->tot_len)-(pIpSrc->ihl<<2)-(pTcpSrc->doff<<2)));

	pTcp->window = pTcpSrc->window;

	//pTcp->fin = 1;
	pTcp->fin = 1; 
    pTcp->ack = 1;

	pTcp->check = 0;
	pTcp->check = ip_in_cksum(pIp, (unsigned short*)pTcp, sizeof(struct tcphdr) + DataLen);
	int rc;

    //pthread_mutex_lock(&g_send_packet_mutex[0]);
	//rc = pcap_inject(ghSniff, gSendBuf, sizeof(ETHDR) + sizeof(IPHDR) + sizeof(TCPHDR) + DataLen);

#ifdef USE_SPINLOCK
            pthread_spin_lock(&g_packet_proc_thread_spinlock);
#else
            pthread_mutex_lock(&g_packet_proc_thread_mutex);
#endif

    int totalLen = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + DataLen;
    if (totalLen > 1500)
    {
        RUN_PRINTF("Error: totalLen > 1500. totalLen=%d content=%s\n", totalLen, content.c_str());
    }

    //printf("send 0 [NC-%s, Thread-%d]\n", nc_index, thread_index);
    rc = pcap_sendpacket(gSysRuntimeInfo[nc_index].ghSender[thread_index], gSysRuntimeInfo[nc_index].sendBuffer[thread_index], totalLen); 
cout << "rc:" << rc << endl;
    if (rc != 0)
    {
        RUN_PRINTF("pcap_sendpacket failed, err=%d info=%s\n", rc, pcap_geterr(gSysRuntimeInfo[nc_index].ghSender[thread_index]));
    }

#ifdef USE_SPINLOCK
            pthread_spin_unlock(&g_packet_proc_thread_spinlock);
#else
            pthread_mutex_unlock(&g_packet_proc_thread_mutex);
#endif

    //pthread_mutex_unlock(&g_send_packet_mutex[0]);

	return 0;
}


#ifndef USE_COOKIE_FOR_CHECKPUSHRATE
int CPacketProcess::CheckPushRate(int nc_id, int thread_index, int pushrate, const std::string &ratekey, const std::string rule, u_int ip, const std::string &agent,
                             const std::string &cookie)
{
    struct tm *ptr;
    time_t lt;
    char   str[20];
    char   ipAndtime[300];
    int    n;
    /*
    memcached_return_t rc;
    size_t len;
	uint32_t flag;
    char  *pValue;
    */

    P_START(5,nc_id,thread_index);

    lt  = time(NULL);
    ptr = localtime(&lt);

    string _rule = rule;
    if (_rule.size() > 50)
    {
        _rule = _rule.substr(0, 50);
    }

    string _agent = agent;
    if (_agent.size() > 150)
    {
        _agent = _agent.substr(0, 150);
    }

    P_END(5,nc_id,thread_index);
    P_START(6,nc_id,thread_index);

    string sIp;
    std::stringstream ss(sIp);
    ss << ip;
    sIp = ss.str();

    string sKey;
    string sValue;

    if (ratekey.empty())
    {
        sKey = _rule + _agent + sIp;
    }
    else
    {
        sKey = ratekey + _agent + sIp;
    }

    P_END(6,nc_id,thread_index);

    P_START(7,nc_id,thread_index);

    //DEBUG_PRINTF("sKey=[%s]\n", sKey.c_str());

    if (pushrate > 0 && pushrate < 60)
    {
        //second
        if (pushrate == 10)
        {
            //per 10 second
            strftime(str, 20, "%m%d%H%M", ptr);
            int asecond=ptr->tm_sec;
            if (asecond>=0&&asecond<10) {
                n = snprintf(ipAndtime, 300, "%s00", str); 
            }else if(asecond>=10&&asecond<20){
                n = snprintf(ipAndtime, 300, "%s10", str); 
            }else if(asecond>=20&&asecond<30){
                n = snprintf(ipAndtime, 300, "%s20", str); 
            }else if(asecond>=30&&asecond<40){
                n = snprintf(ipAndtime, 300, "%s30", str); 
            }else if(asecond>=40&&asecond<50){
                n = snprintf(ipAndtime, 300, "%s40", str); 
            }else {
                n = snprintf(ipAndtime, 300, "%s50", str); 
            }
        }
        else if (pushrate == 1)
        {
            //per 1 second
            strftime(str, 30, "%m%d%H%M%S", ptr);
            n = snprintf(ipAndtime, 300, "%s", str);
        }
    }
    else if (pushrate >= 60 && pushrate < 3600)
    {
        //minute
        if (pushrate == 60)
        {
            //per 1 minute
            strftime(str, 30, "%m%d%H%M", ptr);
            n = snprintf(ipAndtime, 300, "%s", str);
        }
        else if (pushrate == 300)
        {
            //per 5 minutes
            strftime(str, 20, "%m%d%H", ptr); 
            int aminuter=ptr->tm_min;
            if (aminuter>=0&&aminuter<5) {
                n = snprintf(ipAndtime, 300, "%s00", str); 
            }else if(aminuter>=5&&aminuter<10){
                n = snprintf(ipAndtime, 300, "%s05", str); 
            }else if(aminuter>=10&&aminuter<15){
                n = snprintf(ipAndtime, 300, "%s10", str); 
            }else if(aminuter>=15&&aminuter<20){
                n = snprintf(ipAndtime, 300, "%s15", str); 
            }else if(aminuter>=20&&aminuter<25){
                n = snprintf(ipAndtime, 300, "%s20", str); 
            }else if(aminuter>=25&&aminuter<30){
                n = snprintf(ipAndtime, 300, "%s25", str); 
            }else if(aminuter>=30&&aminuter<35){
                n = snprintf(ipAndtime, 300, "%s30", str); 
            }else if(aminuter>=35&&aminuter<40){
                n = snprintf(ipAndtime, 300, "%s35", str); 
            }else if(aminuter>=40&&aminuter<45){
                n = snprintf(ipAndtime, 300, "%s40", str); 
            }else if(aminuter>=45&&aminuter<50){
                n = snprintf(ipAndtime, 300, "%s45", str); 
            }else if(aminuter>=50&&aminuter<55){
                n = snprintf(ipAndtime, 300, "%s50", str); 
            }else {
                n = snprintf(ipAndtime, 300, "%s55", str); 
            }
        }
        else if (pushrate == 1800)
        {
            //per 30 minutes
            strftime(str, 20, "%m%d%H", ptr); 
            int aminuter=ptr->tm_min;
            if (aminuter>=0&&aminuter<30) {
                n = snprintf(ipAndtime, 300, "%s00", str); 
            }else {
                n = snprintf(ipAndtime, 300, "%s30", str); 
            }
        }
    }
    else if (pushrate >= 3600 && pushrate <= 86400)
    {
        if (pushrate == 3600)
        {
            //per 1 hour.
            strftime(str, 20, "%m%d%H", ptr); 
            n = snprintf(ipAndtime, 300, "%s", str);
        }
        else if (pushrate == 43200) 
        {
            //per 12 hour.
            if (ptr->tm_hour < 2) 
            {
                lt  = time(NULL);
                lt -= 2*60*60;
                ptr = localtime(&lt);
            }

            if (ptr->tm_hour >= 0 && ptr->tm_hour < 12) 
            {
                ptr->tm_hour = 0;
                strftime(str, 20, "%m%d%H", ptr);
            }
            else
            {
                ptr->tm_hour = 12;
                strftime(str, 20, "%m%d%H", ptr);
            }
            
            n = snprintf(ipAndtime, 300, "%s", str);
        } 
        else if (pushrate == 86400) 
        {
            //per 24 hour.
            if (ptr->tm_hour < 2) 
            {
                lt  = time(NULL);
                lt -= 2*60*60;
                ptr = localtime(&lt);
            }

            ptr->tm_hour = 0;
            strftime(str, 20, "%m%d%H", ptr);
            
            n = snprintf(ipAndtime, 300, "%s", str);
        }
    }

    sValue = ipAndtime;

    P_END(7,nc_id,thread_index);
    P_START(8,nc_id,thread_index);

/*
    rc = memcached_exist(gSysRuntimeInfo[nc_id].ghMem_user, ipAndtime, strlen(ipAndtime));
    if (MEMCACHED_SUCCESS == rc)
    {
        //DEBUG_PRINTF("memcached exist\n");
        return -1;
    }
    else
    {
        DEBUG_PRINTF("memcached not exist\n");
        rc = memcached_set(gSysRuntimeInfo[nc_id].ghMem_user, ipAndtime, strlen(ipAndtime), "1",strlen("1"), (time_t)0, (uint32_t)0);
        if (rc != MEMCACHED_SUCCESS)
        {
            RUN_PRINTF("memcached_set failed, err=%d\n", rc);
            return -2;
        }
    }
*/

    unordered_map<std::string, std::string>::iterator it;
    it = gSysRuntimeInfo[nc_id].pushTimeMap.find(sKey);

    if (it != gSysRuntimeInfo[nc_id].pushTimeMap.end())
    {
        if (strcmp(ipAndtime, it->second.c_str()) == 0)
        {
            //DEBUG_PRINTF("CheckPushRate: same\n");
            return -9;
        }
        else
        {
            it->second = sValue;
        }
    }
    else
    {
        gSysRuntimeInfo[nc_id].pushTimeMap.insert(std::make_pair(sKey, sValue));
    }

    //DEBUG_PRINTF("CheckPushRate: pushrate=[%d] ipAndtime=[%s] \n", pushrate, ipAndtime);

    P_END(8,nc_id,thread_index);

    return 0;
}

#else

int CPacketProcess::CheckPushRate(int nc_id, int thread_index, int pushrate, const std::string &ratekey, const std::string rule, u_int ip, const std::string &agent,
                                  const std::string &cookie)
{


    P_START(5,nc_id,thread_index);

    if (cookie.find(COOKIE_KEY_1) != cookie.npos)
    {
        return -9;
    }

    P_END(5,nc_id,thread_index);

    return 0;
}

#endif

int CPacketProcess::CheckFileTypeFilter(const HttpRequest &request)
{
    for (std::vector<std::string>::iterator it = gFilterFileType.begin(); it != gFilterFileType.end(); ++it)
    {
        if (request.url.find(*it) != request.url.npos)
        {
            //printf("Leo test: Filter File=%s\n", request.url.c_str());
            return -9;
        }
    }

    return 0;
}

int CPacketProcess::GetRulesByDictionary(const HttpRequest &request, std::vector<CData> &fuzzy_NoHost_Rules, vector<CData>::iterator &it)
{
    bool bFuzzyNoHostMatch = false;
    int url_len = request.url.length();
    const char *pData = request.url.c_str();

    for (int i = 0; i < url_len; i++)
    {
        if (i > 250)
        {
            return -1;
        }
        
        Darts::DoubleArray::result_pair_type results[MAX_DIC_WORD_NUM_RESULTS];
        std::size_t num_results = g_domainRuleNode.m_dictionary.commonPrefixSearch(
                                                                pData, results, MAX_DIC_WORD_NUM_RESULTS);

        pData++;

        if (num_results > 0)
        {
#if 0
            printf("~~~~~~GetRulesByDictionary~~~~~~\nkey=%s, num_results=%d\n", pData-1, num_results); 
            for (std::size_t j = 0; j < (num_results < MAX_DIC_WORD_NUM_RESULTS ? num_results:MAX_DIC_WORD_NUM_RESULTS); j++)
            {
                printf("j%d=%d, %s\n", j, results[j].value, g_domainRuleNode.word_id_2_word_Map[results[j].value].c_str());
            }
            //printf("~~~~~~GetRulesByDictionary~~~~~~\n");
#endif

#if 1
            int loop = (num_results < MAX_DIC_WORD_NUM_RESULTS ? num_results:MAX_DIC_WORD_NUM_RESULTS);
            for (std::size_t j = 0; j < loop; j++)
            {
                CFuzzyData &fuzzyData = g_domainRuleNode.fuzzy_id_Without_Host_DataMap[results[j].value];

                for (std::vector<CData>::iterator it1 = fuzzyData.m_matchRules.begin(); it1 != fuzzyData.m_matchRules.end(); ++it1)
                {
                    //data
                    string objectid = "";
                    string exact = "";
                    string fuzzy = "";
                    string urlaccord = "";
                    string urlfilter = "";
                    string agentfilter = "";
                    string agentmatch = "";
                    string ratekey = "";

                    bool isrefer = false;
                    int pushrate = 0;

                    CData &data_element = *it1;

                    objectid = data_element.objectid;
                    exact = data_element.exact;
                    fuzzy = data_element.fuzzy;
                    urlaccord = data_element.urlaccord;
                    urlfilter = data_element.urlfilter;
                    //agentfilter = data_element.agentfilter;
                    //agentmatch = data_element.agentmatch;
                    //isrefer = data_element.isrefer;
                    pushrate = data_element.pushrate;
                    ratekey = data_element.ratekey;

                    //DEBUG_PRINTF("objectid=%s, exact=%s, fuzzy=%s, urlaccord=%s, urlfilter=%s, pushrate=%d, ratekey=%s\n"
                    //             ,objectid.c_str(), exact.c_str(), fuzzy.c_str(), urlaccord.c_str(), urlfilter.c_str(), pushrate, ratekey.c_str());

                    //DEBUG_PRINTF("request.url = %s\n", request.url.c_str());            


                    if (!fuzzy.empty())
                    {
                        int res = fnmatch(fuzzy.c_str(), request.url.c_str(), 0);
                        if (res == 0)
                        {
                            /*
                            if (!data_element.urlaccord.empty())
                            {
                                for (vector<string>::iterator it2 = data_element.urlaccordSet.begin(); it2 != data_element.urlaccordSet.end(); ++it2)
                                {
                                    if (request.url.find(*it2) == std::string::npos)
                                    {
                                        return -3;
                                    }
                                }
                            } 
                            */ 

                            if (!data_element.urlfilter.empty())
                            {
                                for (vector<string>::iterator it2 = data_element.urlfilterSet.begin(); it2 != data_element.urlfilterSet.end(); ++it2)
                                {
                                    if (request.url.find(*it2) != std::string::npos)
                                    {
                                        return -2;
                                    }
                                }
                            }

                            //it->count++;
                            it = it1;
                            bFuzzyNoHostMatch = true;
                            
                            return 0;
                        }
                        else
                        {
                            continue;
                        }

                        ////正则表达式判断
                        /*			
                        try
                        {
                            boost::regex reg(fuzzy);
                            bool match = boost::regex_match(request.url, reg);
                            if (!match)
                            {
                                continue;
                            }
                        }
                        catch (const exception& e)
                        {
                            LOG4CXX_ERROR(logger, e.what());
                        }
                        */
                    }
                    else
                    {
                        continue;
                    }

                    /*
                    if (!agentfilter.empty())
                    {
                        if (request.UserAgent.find(agentfilter) != std::string::npos)
                        {
                            continue;
                        }
                    }

                    if (!agentmatch.empty())
                    {
                        if (request.url.find(agentmatch) == std::string::npos)
                        {
                            continue;
                        }
                    }

                    if (isrefer && request.Referer.empty())
                    {
                        continue;
                    } 
                    */
                }
            }

#endif
        }
        else
        {
            continue;
        }
    }

    return -5;
}

void CPacketProcess::MakePushCookie(string &cookie, const string &host, int pushrate)
{
	char buf[1024] = {0};

#ifndef USE_COOKIE_FOR_CHECKPUSHRATE
    return;
#else
    if (pushrate != 0)
    {
        std::string _host = host;
        ProcessHost4Cookie(_host);
        sprintf(buf, HEADER_COOKIE, COOKIE_KEY_VALUE_1, _host.c_str(), pushrate);
    }

    cookie = buf;
    return;
#endif
}

void CPacketProcess::UdpProcess(struct iphdr* pIpHdr, char * pSendData, u_int *pSendDataLength)
{
    char user_name[256];
    unsigned int framed_ip_address = 0;

    struct udphdr *pUdpHdr = (struct udphdr*)(((u_char*)pIpHdr) + (pIpHdr->ihl << 2));

    //printf("=Leo=: pUdpHdr->dest=%d m_radiusAccountingPort=%d\n", pUdpHdr->dest, g_systemData.m_radiusAccountingPort);

    unsigned short dest = ntohs(pUdpHdr->dest);
    if (dest == g_systemData.m_radiusAccountingPort) 
    {
        char *pData = ((char*)pUdpHdr) + 8;
        char Code = *pData;
        if (Code == 4)      //Accounting-Request
        {
            unsigned short Length = ntohs(*((unsigned short*)(pData + 2)));
            printf("=Leo=: Length=%d\n", Length);

            int hitCount = 0;
            if (Length > 20 && Length < 600)
            {
                char *pAttrValues = ((char *)pData) + 20;

                for (int i = 0; i < Length - 20; )
                {
                    char t = *(pAttrValues + i);
                    char l = *(pAttrValues + i + 1);
                    //printf("=Leo=: t=%d l=%d\n", t, l);

                    if (t == 1)     //User-Name
                    {
                        hitCount++;
                        memcpy(user_name, (pAttrValues + i + 1 + 1), l);
                        printf("=Leo=: user_name=%s\n", user_name);
                    }
                    else if (t == 8) 
                    {
                        char str[64];
                        hitCount++;
                        framed_ip_address = *((unsigned int*)(pAttrValues + i + 1 + 1));

                        IpIntToStr(framed_ip_address, str);
                        printf("=Leo=: framed_ip_address1=%d framed_ip_address2=%s framed_ip_address3=%d\n", framed_ip_address, str, ntohl(IPStrToInt(str)));
                    }

                    if (hitCount >= 2)
                    {
                        string sUser_Name = user_name;

                        //sUser_Name = "18900000000";       //打桩测试

                        unordered_map<string, unsigned int>::iterator it = g_systemData.m_User2IpBlacklist.find(sUser_Name);
                        if (it != g_systemData.m_User2IpBlacklist.end())
                        {
                            if (it->second != framed_ip_address)
                            {
                                //Print user2ip and ip2user
                                printf("******************************\n");
                                PrintUser2IpBlacklist(g_systemData.m_User2IpBlacklist);
                                PrintIp2UserBlacklist(g_systemData.m_Ip2UserBlacklist);

                                g_systemData.m_Ip2UserBlacklist.erase(it->second);
                                g_systemData.m_Ip2UserBlacklist.insert(std::make_pair(framed_ip_address, sUser_Name));
                                it->second = framed_ip_address;

                                //Print user2ip and ip2user
                                printf("##############################\n");
                                PrintUser2IpBlacklist(g_systemData.m_User2IpBlacklist);
                                PrintIp2UserBlacklist(g_systemData.m_Ip2UserBlacklist);
                            }
                        }

                        break;
                    }

                    i += l;
                }
            }
        }
    }
    else if (dest == g_systemData.m_radiusAccessPort)
    {
    }
    else if (dest == DNS_UDP_PORT)
    {
        struct dnshdr *dnsh;
        struct dnshdr *send_dnsh;
        u_char *tmp;
    	u_char *label;
    	const char *data;
    	const u_char *end;
        u_char *dnsAnswer;
    	uint16_t len, qtype = 0;
    	int i;
        u_char buf[BUFSIZ]; /* Label buffer */
        CDnsData *pDnsData = NULL;

        dnsh = (struct dnshdr *)(((u_char *)pUdpHdr) + 8);
        dnsh->id      = ntohs(dnsh->id);
        dnsh->flags   = ntohs(dnsh->flags);
        dnsh->qdcount = ntohs(dnsh->qdcount);
        dnsh->ancount = ntohs(dnsh->ancount);
        dnsh->nscount = ntohs(dnsh->nscount);
        dnsh->arcount = ntohs(dnsh->arcount);

        /* Disregard malformed packets */
        if (!dnsh->ancount && !dnsh->qdcount)
        {
            return;
        }

        u_int iUdpLen = ntohs(pUdpHdr->len);
        end = ((u_char *)pUdpHdr) + iUdpLen;

        /* Parse the Question section */
    	tmp = (u_char *)(((u_char *)pUdpHdr) + 8 + 12);
    	for (i=0;i<dnsh->qdcount;i++) {
    		/* Get the first question's label and question type */
            if (!qtype)
            {
                label = dns_label_to_str(&tmp, buf, BUFSIZ,
                                         (u_char *)dnsh, end);

//              if (strcmp((const char*)label, "news.qq.com") != 0 && strcmp((const char*)label, "www.163.com") && strcmp((const char*)label, "www.sina.com.cn")
//                  && strcmp((const char*)label, "www.sohu.com"))
//              {
//                  return;
//              }

                std::string sDomain(reinterpret_cast<char*>(label));
                unordered_map<string, CDnsData*>::iterator it1 = g_domainRuleNode.exactDnsDataMap.find(sDomain);
                if (it1 == g_domainRuleNode.exactDnsDataMap.end())
                {
                    return;
                }

                pDnsData = it1->second;
                if (pDnsData == NULL) 
                {
                    return;
                }

                if (pDnsData->src_domain_ip[0] == 0)
                {
                    return;
                }

                RUN_PRINTF("label=%s\n", label);

                tmp++;
                qtype = ntohs(*(uint16_t *)tmp);
            }
            else
            {
                if (*tmp & 0xc0) tmp += 2;
                else tmp = skip_dns_label(tmp);
            }

    		/* Skip type and class */
    		tmp += 4;
    		if (tmp >= end)
            {
                break;
            }
    	}

        //转换回网络序
        dnsh->id      = ntohs(dnsh->id);
        dnsh->flags   = ntohs(dnsh->flags);
        dnsh->qdcount = ntohs(dnsh->qdcount);
        dnsh->ancount = ntohs(dnsh->ancount);
        dnsh->nscount = ntohs(dnsh->nscount);
        dnsh->arcount = ntohs(dnsh->arcount);

        memcpy(pSendData, dnsh, ntohs(pUdpHdr->len) - 8);

        send_dnsh = (struct dnshdr *)pSendData;
        send_dnsh->flags = ntohs(0x8180);
        send_dnsh->ancount = ntohs(1);

        //https://segmentfault.com/a/1190000009369381
        dnsAnswer = ((u_char *)send_dnsh) + ntohs(pUdpHdr->len) - 8;

//        //Type CNAME Begin
//        dnsAnswer[0] = 0xC0;
//        dnsAnswer[1] = 0x0C;      //域名 Name
//
//        dnsAnswer[2] = 0x00;
//        dnsAnswer[3] = 0x05;      //Type CNAME
//
//        dnsAnswer[4] = 0x00;
//        dnsAnswer[5] = 0x01;      //Class
//
//        dnsAnswer[6] = 0x00;
//        dnsAnswer[7] = 0x00;
//        dnsAnswer[8] = 0x00;
//        dnsAnswer[9] = 0x1e;      //Time to live
//
//        dnsAnswer[10] = 0x00;
//        dnsAnswer[11] = 0x0f;     //Data length
//
//        dnsAnswer[12] = 0x03;
//        dnsAnswer[13] = 0x77;
//        dnsAnswer[14] = 0x77;
//        dnsAnswer[15] = 0x77;
//        dnsAnswer[16] = 0x05;
//        dnsAnswer[17] = 0x62;
//        dnsAnswer[18] = 0x61;
//        dnsAnswer[19] = 0x69;
//        dnsAnswer[20] = 0x64;
//        dnsAnswer[21] = 0x75;
//        dnsAnswer[22] = 0x03;
//        dnsAnswer[23] = 0x63;
//        dnsAnswer[24] = 0x6f;
//        dnsAnswer[25] = 0x6d;
//        dnsAnswer[26] = 0x00;
//
//        //Type CNAME End
//
//
//        //Type A Begin
//        dnsAnswer[27] = 0xC0;
//        dnsAnswer[28] = 0x29;      //域名 Name
//
//        dnsAnswer[29] = 0x00;
//        dnsAnswer[30] = 0x01;      //Type A
//
//        dnsAnswer[31] = 0x00;
//        dnsAnswer[32] = 0x01;      //Class
//
//        dnsAnswer[33] = 0x00;
//        dnsAnswer[34] = 0x00;
//        dnsAnswer[35] = 0x00;
//        dnsAnswer[36] = 0x1e;      //Time to live
//
//        dnsAnswer[37] = 0x00;
//        dnsAnswer[38] = 0x04;     //Data length
//
////      dnsAnswer[39] = 0x0E;
////      dnsAnswer[40] = 0xD7;
////      dnsAnswer[41] = 0xB1;
////      dnsAnswer[42] = 0x27;     //IP Baidu
//
//        dnsAnswer[39] = 0x74;
//        dnsAnswer[40] = 0x3E;
//        dnsAnswer[41] = 0xBB;
//        dnsAnswer[42] = 0x69;     //IP
//        //Type A End



        BuildDnsAnswer_Type2(send_dnsh, dnsAnswer, pUdpHdr->len, pSendDataLength, pDnsData);

        //*pSendDataLength = ntohs(pUdpHdr->len) - 8 + 27 + 16; //8:UDP Header 16:Answer
        //*pSendDataLength = ntohs(pUdpHdr->len) - 8 + 16; //8:UDP Header 16:Answer
ret:
        return;
    }
}

//构造单个A应答
void CPacketProcess::BuildDnsAnswer_Type1(struct dnshdr *_dnshdr, u_char * dnsAnswer, u_int udpLen, u_int *pSendDataLength, CDnsData *pDnsData)
{
    //Type A Begin
    dnsAnswer[0] = 0xC0;
    dnsAnswer[1] = 0x0C;      //域名 Name

    dnsAnswer[2] = 0x00;
    dnsAnswer[3] = 0x01;      //Type A

    dnsAnswer[4] = 0x00;
    dnsAnswer[5] = 0x01;      //Class

    dnsAnswer[6] = 0x00;
    dnsAnswer[7] = 0x00;
    dnsAnswer[8] = 0x00;
    dnsAnswer[9] = 0x1e;      //Time to live

    dnsAnswer[10] = 0x00;
    dnsAnswer[11] = 0x04;     //Data length

    dnsAnswer[12] = 0x74;
    dnsAnswer[13] = 0x3E;
    dnsAnswer[14] = 0xBB;
    dnsAnswer[15] = 0x69;     //IP
    //Type A End

    _dnshdr->ancount = ntohs(1);

    *pSendDataLength = ntohs(udpLen) - 8 + 16; //8:UDP Header 16:Answer
}

//构造单个A应答
void CPacketProcess::BuildDnsAnswer_Type2(struct dnshdr *_dnshdr, u_char * dnsAnswer, u_int udpLen, u_int *pSendDataLength, CDnsData *pDnsData)
{
    if (pDnsData == NULL)
    {
        return;
    }

    //Type A Begin
    dnsAnswer[0] = 0xC0;
    dnsAnswer[1] = 0x0C;      //域名 Name

    dnsAnswer[2] = 0x00;
    dnsAnswer[3] = 0x01;      //Type A

    dnsAnswer[4] = 0x00;
    dnsAnswer[5] = 0x01;      //Class

    dnsAnswer[6] = 0x00;
    dnsAnswer[7] = 0x00;
    dnsAnswer[8] = 0x00;
    dnsAnswer[9] = 0x1e;      //Time to live

    dnsAnswer[10] = 0x00;
    dnsAnswer[11] = 0x04;     //Data length

    dnsAnswer[12] = g_dns_location_server[0];
    dnsAnswer[13] = g_dns_location_server[1];
    dnsAnswer[14] = g_dns_location_server[2];
    dnsAnswer[15] = g_dns_location_server[3];     //IP
    //Type A End

        //Type A Begin
    dnsAnswer[16] = 0xC0;
    dnsAnswer[17] = 0x0C;      //域名 Name

    dnsAnswer[18] = 0x00;
    dnsAnswer[19] = 0x01;      //Type A

    dnsAnswer[20] = 0x00;
    dnsAnswer[21] = 0x01;      //Class

    dnsAnswer[22] = 0x00;
    dnsAnswer[23] = 0x00;
    dnsAnswer[24] = 0x00;
    dnsAnswer[25] = 0x1e;      //Time to live

    dnsAnswer[26] = 0x00;
    dnsAnswer[27] = 0x04;     //Data length

    dnsAnswer[28] = pDnsData->src_domain_ip[0];
    dnsAnswer[29] = pDnsData->src_domain_ip[1];
    dnsAnswer[30] = pDnsData->src_domain_ip[2];
    dnsAnswer[31] = pDnsData->src_domain_ip[3];     //IP
    //Type A End

    _dnshdr->ancount = ntohs(2);

    *pSendDataLength = ntohs(udpLen) - 8 + 16 + 16; //8:UDP Header 16:Answer
}


