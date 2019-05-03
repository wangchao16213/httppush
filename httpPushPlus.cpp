#include <iostream>
#include <vector>
#include <chrono>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <linux/if.h>

#include <unistd.h>
#include <sstream>
#include <curl/curl.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/socket.h>

#include "data/SystemData.h"
#include "data/DomainRuleNode.h"
#include "include/common_type.h"
#include "ThreadPool.h"
#include "PacketProcess.h"
#include "include/rapidjson/document.h"
#include "include/rapidjson/writer.h"
#include "include/rapidjson/stringbuffer.h"

#include "check.h"

using std::cout;
using std::endl;

//#ifdef ROUTEMAC
//char gaRouteMac[ETH_ALEN]={ROUTEMAC};
//#else
//char gaRouteMac[ETH_ALEN]={char(0x70),char(0x7b),char(0xe8),char(0x34),char(0x37),char(0x56)};//jiang'xi'yidong
//#endif

//#ifdef IFMAC
//char gaIFMac[ETH_ALEN]={IFMAC};
//#else
//wang ka
//char gaIFMac[ETH_ALEN]={0x00,0x0C,0x29,0x37,0x39,0x77};//local
//char gaIFMac[ETH_ALEN]={0x00,0x1B,0x21,0x54,0xC9,0xD8};//jiang'xi'tie'tong
//char gaIFMac[ETH_ALEN]={0xC8,0x0A,0xA9,0x88,0x21,0x44};//hai nan
//char gaIFMac[ETH_ALEN]={0xC8,0x0A,0xA9,0x57,0x6E,0xA4};//pu tian
//char gaIFMac[ETH_ALEN]={char(0x00),char(0x26),char(0x9E),char(0xB5),char(0xA2),char(0xF0)};//jiang'xi'yidong
//#endif

SYS_RUNTIME_INFO gSysRuntimeInfo[MAX_SNIFFER_NC_COUNT];
//const char * gSniffEth="eth1";
//const char * gSendEth="eth0";
struct timeval gTime = {0};
struct tm gTM = {0};

int gDebugLv = 0;

ThreadPool *g_pPool = NULL;

int g_cleanup_flag = 0;
int g_systemExit = 0;

//std::string g_pointid;              //渠道ID
//std::string g_sign;                 //本机唯一标识
//std::string g_version;              //软件版本

std::stringstream g_ss1; //接收REST API应答数据

//int g_card_num;                 //网卡数量

CSystemData g_systemData;

CDomainRuleNode g_domainRuleNode;

u_char g_routermac[6];
u_char g_sendermac[6];

int g_dns_location_server[4];

#ifdef USE_SPINLOCK
pthread_spinlock_t g_packet_proc_thread_spinlock;
#else
pthread_mutex_t g_packet_proc_thread_mutex;
#endif

pthread_mutex_t g_send_packet_mutex[2];

std::vector<std::string> gFilterFileType;

int InitVars();
int InitSys();
int InitDev();
int setSender();
static void cleanup(int signo);
int InitGetControl();
int InitGetBlacklists();
int get_mac(char *card, char *mac);
void calc_md5(const unsigned char *data, unsigned char *md5);
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);
int SaveInitEth(char *json);
int SaveGetControl(char *json);
int SaveGetBlacklists(char *json);
std::string &trim(std::string &s);

string &replace_all(string &str, const string &old_value, const string &new_value);

void Save2Dictionary(CData &data, u_long &allFuzzyWordCount);
void BuildDictionary();
void SplitWord(std::string str, const std::string &pattern, std::vector<std::string> &words);
void TestDictionary();

int StatInfoThread();
int BuildStatInfo(std::string &json);
int ClearStatInfo();

int UserIpInfoThread();
int BuildUserIpInfo(std::string &json);

int VerifyLicense();

int GetHostThread();

int main(int argc, char *argv[])
{
    if (argc > 1)
    {
        if (strcmp(argv[1], "md5") == 0)
        {
            RUN_PRINTF("md5sum httpPushPlusBin|cut -d ' ' -f1\n");
            return -10;
        }

        g_systemData.m_md5 = argv[1];
        RUN_PRINTF("Parameter md5: %s\n", g_systemData.m_md5.c_str());
    }
    else
    {
        RUN_PRINTF("Parameter error.\n");
        return -1;
    }

    int err = InitSys();
    if (err != 0)
    {
        RUN_PRINTF("InitSys() failed. err=%d\n", err);
        return err;
    }

    signal(SIGINT, cleanup);
    //signal(SIGCHLD, sig_chld_func);
    signal(SIGTERM, cleanup);
    signal(SIGHUP, cleanup);

    try
    {
        g_pPool->enqueue(GetHostThread);

        for (vector<CDeviceData *>::const_iterator it = g_systemData.m_deviceDataSet.begin(); it != g_systemData.m_deviceDataSet.end(); ++it)
        {
            g_pPool->enqueue(CPacketProcess::StartSnifferPacket, *it);
        }

        sleep(1);
        g_pPool->enqueue(StatInfoThread);
        g_pPool->enqueue(UserIpInfoThread);

        do
        {
            sleep(30);
        } while (true);
    }
    catch (std::exception &e)
    {
        cout << "some unhappy happened... " << std::this_thread::get_id() << e.what() << endl;
    }

    cleanup(0);

    return (0);
}

/*
int InitDebugVars()
{
    g_systemData.m_sign = "Host_Debug_0";

#ifdef _DEBUG_SERVER_TEST
    CDeviceData devSet[2];
    devSet[0].m_ID = 0;
    devSet[0].m_routerMac = "01:01:01:01:01:AA";
    devSet[0].m_sendNetworkCard.m_name = "eth5";
    devSet[0].m_sendNetworkCard.m_mac = "01:01:01:01:01:01";
    devSet[0].m_snifferNetworkCard.m_name = "eth2";
    devSet[0].m_snifferNetworkCard.m_mac = "02:02:02:02:02:02";
    devSet[0].m_snifferThreadCount = 8;

    devSet[1].m_ID = 1;
    devSet[1].m_routerMac = "01:01:01:01:01:AA";
    devSet[1].m_sendNetworkCard.m_name = "eth5";
    devSet[1].m_sendNetworkCard.m_mac = "01:01:01:01:01:01";
    devSet[1].m_snifferNetworkCard.m_name = "eth3";
    devSet[1].m_snifferNetworkCard.m_mac = "03:03:03:03:03:03";
    //devSet[01].m_snifferThreadCount = 8;

    g_systemData.m_deviceDataSet.push_back(devSet[0]);
    g_systemData.m_deviceDataSet.push_back(devSet[1]);
    g_systemData.m_snifferThreadCount = 8;
#else
    CDeviceData devSet[2];
    devSet[0].m_ID = 0;
    devSet[0].m_routerMac = "00:50:56:e9:bc:1c";
    devSet[0].m_sendNetworkCard.m_name = "eth3";
    devSet[0].m_sendNetworkCard.m_mac = "00:0C:29:8F:A1:29";
    devSet[0].m_snifferNetworkCard.m_name = "eth3";
    devSet[0].m_snifferNetworkCard.m_mac = "00:0C:29:8F:A1:29";
    //devSet[0].m_snifferThreadCount = 4;

    g_systemData.m_deviceDataSet.push_back(devSet[0]);
    g_systemData.m_snifferThreadCount = 4;
#endif
} 
*/

int InitVars()
{
    //InitDebugVars();

    // {".png", ".jpg", ".css", ".gif", ".jpeg", ".bmp", ".webp", ".xml", ".mp4", ".mp3", ".JPEG"};
    gFilterFileType.clear();
    gFilterFileType.push_back(".png");
    gFilterFileType.push_back(".jpg");
    gFilterFileType.push_back(".css");
    gFilterFileType.push_back(".gif");
    gFilterFileType.push_back(".jpeg");
    gFilterFileType.push_back(".bmp");
    gFilterFileType.push_back(".webp");
    gFilterFileType.push_back(".xml");
    gFilterFileType.push_back(".mp4");
    gFilterFileType.push_back(".mp3");
    gFilterFileType.push_back(".JPEG");
    gFilterFileType.push_back(".zip");
    gFilterFileType.push_back(".rar");
    gFilterFileType.push_back(".json");

    g_systemData.m_snifferThreadCount = 0;
    g_systemData.m_fuzzy_with_host_thread_count = 0;
    g_systemData.m_fuzzy_without_host_thread_count = 0;

    g_systemData.m_radiusAccessPort = 1645;
    g_systemData.m_radiusAccountingPort = 1646;

    return 0;
}

int InitSys()
{
    char szBuf[256] = {0};
    time_t timer = time(NULL);
    strftime(szBuf, sizeof(szBuf), "%Y-%m-%d %H:%M:%S", localtime(&timer));

    RUN_PRINTF("HttpPushPlus system is booting... [%s] [%s]\n", SOFTWARE_VERSION, szBuf);

#ifdef USE_SPINLOCK
    pthread_spin_init(&g_packet_proc_thread_spinlock, 0);
#else
    pthread_mutex_init(&g_packet_proc_thread_mutex, NULL);
#endif

    for (int i = 0; i < 2; i++)
    {
        pthread_mutex_init(&g_send_packet_mutex[i], NULL);
    }

    int err = InitVars();
    if (err != 0)
    {
        return err;
    }

    err = InitDev();
    if (err != 0)
    {
        return err;
    }

    //初始化curl
    curl_global_init(CURL_GLOBAL_ALL);

    //  if (VerifyLicense() != 0)
    //  {
    //      return -99;
    //  }

    err = InitGetControl();
    if (err != 0)
    {
        return err;
    }

    err = InitGetBlacklists();
    if (err != 0)
    {
        return err;
    }

    g_pPool = new ThreadPool(25);

    return 0;
}

int InitDev()
{
    gettimeofday(&gTime, NULL);
    localtime_r(&gTime.tv_sec, &gTM);

    u_char md5[33] = {0};
    struct ifaddrs *interface_info, *interface_tmp;
    char nc_mac[50] = {0};

    g_systemData.m_pointid = "VMWARE1"; //测试用
    g_systemData.m_version = "1.0.1";

    int loop_num = 0;

    /*获取接口信息*/
    int ret = getifaddrs(&interface_info);
    if (ret != RETURN_OK)
    {
        DEBUG_PRINTF("getifaddrs fail [%s, %d]\n", __func__, __LINE__);
        return ERROR_SYS;
    }

    /*从接口信息中提取网卡名字*/
    for (interface_tmp = interface_info; interface_tmp != NULL; interface_tmp = interface_tmp->ifa_next)
    {
        if (0 == loop_num)
        {
            memset(nc_mac, 0x00, sizeof(nc_mac));
            get_mac(interface_tmp->ifa_name, nc_mac);
            if (strcmp(nc_mac, "00:00:00:00:00:00") != 0)
            {
                DEBUG_PRINTF("name = %s, mac = %s\n", interface_tmp->ifa_name, nc_mac);
                loop_num++;
            }
        }

        /*
		addr_b = (struct sockaddr_in *)interface_tmp->ifa_addr;
		if((2 == addr_b->sin_family)&&(strcmp(interface_tmp->ifa_name, "lo")))
		{
			strcpy(g_serve_ip, inet_ntoa(addr_b->sin_addr));
		}
			
		if(strstr(net_card, interface_tmp->ifa_name))
		{
			continue;
		}
		sprintf(net_card + strlen(net_card), "%s|", interface_tmp->ifa_name);
        */
    }

    calc_md5((const u_char *)nc_mac, md5);
    string s(&md5[0], &md5[strlen((char *)md5)]);

    g_systemData.m_sign = s;

    do
    {
        CURL *curl;
        CURLcode res;
        char url[5120];

        g_ss1.str("");
        g_ss1.clear();

        curl = curl_easy_init();

        if (curl)
        {
            //"api/init_eth?pointid=%s&sign=%s&version=%s"

            struct MemoryStruct chunk;

            chunk.memory = (char *)malloc(1); /* will be grown as needed by the realloc above */
            chunk.size = 0;                   /* no data at this point */

            std::stringstream ss_temp;
            ss_temp << REST_API_URL_BASE << "api/init_eth?pointid=" << g_systemData.m_pointid << "&sign=" << g_systemData.m_sign << "&version=" << g_systemData.m_version;
            std::string str_full_url;
            ss_temp >> str_full_url;
            cout << str_full_url << endl;

            curl_easy_setopt(curl, CURLOPT_URL, str_full_url.c_str());

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

            CURLcode code = curl_easy_perform(curl);

            if (code == CURLE_OK)
            {
                DEBUG_PRINTF("[%s]\n", chunk.memory);

                ret = SaveInitEth(chunk.memory);
                if (ret != 0)
                {
                    return ret;
                }

                break;
            }
            else
            {
                RUN_PRINTF("curl_easy_perform return %d\n", code);
            }

            curl_easy_cleanup(curl);
            free(chunk.memory);

            sleep(10);
        }

    } while (true);

    return RETURN_OK;
}

int setSender()
{
    char aErrBuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;

    if (g_systemData.m_deviceDataSet.size() <= 0)
    {
        RUN_PRINTF("setSender(): No Network Card configuration.\n");
        return -1;
    }

    for (vector<CDeviceData *>::const_iterator it = g_systemData.m_deviceDataSet.begin(); it != g_systemData.m_deviceDataSet.end(); ++it)
    {
        for (int i = 0; i < g_systemData.m_totalThreadCount; i++)
        {
            if ((*it)->m_snifferNetworkCard.m_name.compare((*it)->m_sendNetworkCard.m_name) != 0)
            {
                if (gSysRuntimeInfo[(*it)->m_ID].ghSender[i])
                {
                    pcap_close(gSysRuntimeInfo[(*it)->m_ID].ghSender[i]);
                }

                gSysRuntimeInfo[(*it)->m_ID].ghSender[i] = pcap_open_live((*it)->m_sendNetworkCard.m_name.c_str(), 1, 1, -1, aErrBuf);

                if (gSysRuntimeInfo[(*it)->m_ID].ghSender[i] == NULL)
                {
                    RUN_PRINTF("setSender(): pcap_open_live() failed:%s\n", aErrBuf);
                    exit(-1);
                }

                if (pcap_compile(gSysRuntimeInfo[(*it)->m_ID].ghSender[i], &filter, "not ip", 1, PCAP_NETMASK_UNKNOWN) == -1)
                {
                    RUN_PRINTF("setSender(): Error on pcap_compile\n");
                    exit(-1);
                }

                //DEBUG_PRINTF("setSender()\n");
            }
        }
    }

    return 0;
}

extern unsigned long long temp99;
extern unsigned long long temp_count[];

static void cleanup(int signo)
{
    struct pcap_stat stat;

    RUN_PRINTF("System cleanup...\n");

    if (0 == g_cleanup_flag)
    {
        g_cleanup_flag = 1;
        g_systemExit = 1;

        usleep(10);

#ifdef USE_SPINLOCK
        pthread_spin_unlock(&g_packet_proc_thread_spinlock);
#else
        pthread_mutex_unlock(&g_packet_proc_thread_mutex);
#endif

        for (int i = 0; i < 2; i++)
        {
            pthread_mutex_unlock(&g_send_packet_mutex[i]);
        }

        if (g_pPool)
        {
            RUN_PRINTF("Destroy thread pool...\n");
            delete g_pPool;
            g_pPool = NULL;
            RUN_PRINTF("Destroy thread pool end.\n");
        }

        usleep(10000);

        for (vector<CDeviceData *>::const_iterator it = g_systemData.m_deviceDataSet.begin(); it != g_systemData.m_deviceDataSet.end(); ++it)
        {
            int totalThreadCount = g_systemData.m_snifferThreadCount + g_systemData.m_fuzzy_with_host_thread_count + g_systemData.m_fuzzy_without_host_thread_count;
            for (int i = 0; i < totalThreadCount; i++)
            {
                memset(&stat, 0, sizeof(struct pcap_stat));

                if (pcap_stats(gSysRuntimeInfo[(*it)->m_ID].ghSniff[i], &stat) < 0)
                {
                    RUN_PRINTF("pcap_stats: %s\n", pcap_geterr(gSysRuntimeInfo[(*it)->m_ID].ghSniff[i]));
                }

                RUN_PRINTF("\nstatistics [NC-%s Thread-%d]:\n\tps_recv   :%12u\n\tps_drop   :%12u\n\tps_ifdrop :%12u\n\n", (*it)->m_snifferNetworkCard.m_name.c_str(), i, stat.ps_recv, stat.ps_drop, stat.ps_ifdrop);

                printf("count=%d, err0=%d, err-1=%d, err-2=%d\n", temp_count[0], temp_count[0], temp_count[1], temp_count[2]);

                pcap_close(gSysRuntimeInfo[(*it)->m_ID].ghSniff[i]);
            }
        }

#ifdef USE_SPINLOCK
        pthread_spin_destroy(&g_packet_proc_thread_spinlock);
#else
        pthread_mutex_destroy(&g_packet_proc_thread_mutex);
#endif

        for (int i = 0; i < 2; i++)
        {
            pthread_mutex_destroy(&g_send_packet_mutex[i]);
        }

        for (vector<CDeviceData *>::iterator it = g_systemData.m_deviceDataSet.begin(); it != g_systemData.m_deviceDataSet.end(); ++it)
        {
            CDeviceData *temp = *it;
            delete temp;
            temp = NULL;
        }

        g_systemData.m_deviceDataSet.clear();

        /* we're done with libcurl, so clean it up */
        curl_global_cleanup();
    }

    char szBuf[256] = {0};
    time_t timer = time(NULL);
    strftime(szBuf, sizeof(szBuf), "%Y-%m-%d %H:%M:%S", localtime(&timer));

    RUN_PRINTF("System cleanup end. [%s]\n", szBuf);

    exit(0);
}

/*
description:获取mac信息
param[in]:card 网卡
param[out]:mac指向一段合法内存，返回mac地址
return:成功返回returnok,失败返回错误标识
author:xcl
date:2014.8.2
version:1.0.0
*/
int get_mac(char *card, char *mac)
{
    int sockfd;
    struct ifreq tmp;
    char mac_addr[BUF_SIZE_50] = {0};

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("create socket fail\n");
        return ERROR_SYS;
    }

    memset(&tmp, 0, sizeof(struct ifreq));
    strncpy(tmp.ifr_name, card, sizeof(tmp.ifr_name) - 1);
    if ((ioctl(sockfd, SIOCGIFHWADDR, &tmp)) < 0)
    {
        DEBUG_PRINTF("mac ioctl error\n");
        return ERROR_SYS;
    }

    sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
            (unsigned char)tmp.ifr_hwaddr.sa_data[0],
            (unsigned char)tmp.ifr_hwaddr.sa_data[1],
            (unsigned char)tmp.ifr_hwaddr.sa_data[2],
            (unsigned char)tmp.ifr_hwaddr.sa_data[3],
            (unsigned char)tmp.ifr_hwaddr.sa_data[4],
            (unsigned char)tmp.ifr_hwaddr.sa_data[5]);

    close(sockfd);
    memcpy(mac, mac_addr, strlen(mac_addr));
    mac[strlen(mac_addr)] = '\0';
    return RETURN_OK;
}

void calc_md5(const unsigned char *data, unsigned char *md5)
{
    //unsigned char *data = "123";
    unsigned char md[16];
    int i;
    char tmp[3] = {0}; //,buf[33]={0};
    MD5(data, strlen((const char *)data), md);

    for (i = 0; i < 16; i++)
    {
        sprintf(tmp, "%02X", md[i]);
        strcat((char *)md5, tmp);
    }

    DEBUG_PRINTF("md5:%s\n", md5);
}

/*
size_t init_eth_write_data(void *ptr, size_t size, size_t nmemb, void *userp)
{
    g_ss1 << (char*)ptr;

    DEBUG_PRINTF("%s", (char*)ptr);

	return size * nmemb;
} 
*/

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    mem->memory = (char *)realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL)
    {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

int InitGetControl()
{
    do
    {
        CURL *curl;
        CURLcode res;
        char url[5120];

        g_ss1.str("");
        g_ss1.clear();

        curl = curl_easy_init();

        if (curl)
        {
            //"api/get_control?pointid=%s&sign=%s&version=%s"

            struct MemoryStruct chunk;

            chunk.memory = (char *)malloc(1); /* will be grown as needed by the realloc above */
            chunk.size = 0;                   /* no data at this point */

            std::stringstream ss_temp;
            ss_temp << REST_API_URL_BASE << "api/get_control?pointid=" << g_systemData.m_pointid << "&sign=" << g_systemData.m_sign << "&version=" << g_systemData.m_version;
            std::string str_full_url;
            ss_temp >> str_full_url;
            cout << str_full_url << endl;

            curl_easy_setopt(curl, CURLOPT_URL, str_full_url.c_str());

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

            CURLcode code = curl_easy_perform(curl);

            if (code == CURLE_OK)
            {
                DEBUG_PRINTF("[%s]\n", chunk.memory);

                SaveGetControl(chunk.memory);

                break;
            }
            else
            {
                RUN_PRINTF("curl_easy_perform return %d\n", code);
            }

            curl_easy_cleanup(curl);
            free(chunk.memory);

            sleep(10);
        }

    } while (true);

    return RETURN_OK;
}

int InitGetBlacklists()
{
    do
    {
        CURL *curl;
        CURLcode res;
        char url[5120];

        g_ss1.str("");
        g_ss1.clear();

        curl = curl_easy_init();

        if (curl)
        {
            //"api/get_blacklists?pointid=%s&sign=%s&version=%s"

            struct MemoryStruct chunk;

            chunk.memory = (char *)malloc(1); /* will be grown as needed by the realloc above */
            chunk.size = 0;                   /* no data at this point */

            std::stringstream ss_temp;
            ss_temp << REST_API_URL_BASE << "api/get_blacklists?pointid=" << g_systemData.m_pointid << "&sign=" << g_systemData.m_sign << "&version=" << g_systemData.m_version;
            //ss_temp << "http://rapapi.org/mockjsdata/27575/" << "api/get_blacklists?pointid=" << g_systemData.m_pointid << "&sign=" << g_systemData.m_sign << "&version=" << g_systemData.m_version;

            std::string str_full_url;
            ss_temp >> str_full_url;
            cout << str_full_url << endl;

            curl_easy_setopt(curl, CURLOPT_URL, str_full_url.c_str());

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

            CURLcode code = curl_easy_perform(curl);

            if (code == CURLE_OK)
            {
                //DEBUG_PRINTF("[%s]\n", chunk.memory);

                SaveGetBlacklists(chunk.memory);

                break;
            }
            else
            {
                RUN_PRINTF("curl_easy_perform return %d\n", code);
            }

            curl_easy_cleanup(curl);
            free(chunk.memory);

            sleep(10);
        }

    } while (true);

    return RETURN_OK;
}

int SaveInitEth(char *json)
{
    std::string _routermac;
    std::string _dns_location_server;
    std::string _if_ether_sender_name;
    std::string _if_ether_sender_mac;
    std::vector<std::string> _if_ether_sniffer_set;

    rapidjson::Document document;

    if (document.Parse(json).HasParseError())
    {
        return ERROR_FAIL;
    }

    DEBUG_PRINTF("-- init_eth --\n");

    if (document.HasMember("state"))
    {
        g_systemData.m_stat = document["state"].GetInt();
        DEBUG_PRINTF("m_stat %d\n", g_systemData.m_stat);
    }

    if (document.HasMember("data"))
    {
        const rapidjson::Value &data_json = document["data"];
        for (rapidjson::Value::ConstMemberIterator iter = data_json.MemberBegin(); iter != data_json.MemberEnd(); ++iter)
        {
            DEBUG_PRINTF("data %s\n", iter->name.GetString());
            if (strcmp(iter->name.GetString(), "threadCount") == 0)
            {
                g_systemData.m_snifferThreadCount = iter->value.GetInt();
                DEBUG_PRINTF("m_snifferThreadCount %d\n", g_systemData.m_snifferThreadCount);

                if (g_systemData.m_totalThreadCount > MAX_SNIFFER_THREAD_COUNT)
                {
                    RUN_PRINTF("Err: g_systemData total ThreadCount > MAX_SNIFFER_THREAD_COUNT [%s, %d]\n", __func__, __LINE__);
                    return ERROR_SYS;
                }
            }
            else if (strcmp(iter->name.GetString(), "fuzzy_with_host_thread_count") == 0)
            {
                g_systemData.m_fuzzy_with_host_thread_count = iter->value.GetInt();
                DEBUG_PRINTF("m_fuzzy_with_host_thread_count %d\n", g_systemData.m_fuzzy_with_host_thread_count);

                if (g_systemData.m_totalThreadCount > MAX_SNIFFER_THREAD_COUNT)
                {
                    RUN_PRINTF("Err: g_systemData total ThreadCount > MAX_SNIFFER_THREAD_COUNT [%s, %d]\n", __func__, __LINE__);
                    return ERROR_SYS;
                }
            }
            else if (strcmp(iter->name.GetString(), "fuzzy_without_host_thread_count") == 0)
            {
                g_systemData.m_fuzzy_without_host_thread_count = iter->value.GetInt();
                DEBUG_PRINTF("m_fuzzy_without_host_thread_count %d\n", g_systemData.m_fuzzy_without_host_thread_count);

                if (g_systemData.m_totalThreadCount > MAX_SNIFFER_THREAD_COUNT)
                {
                    RUN_PRINTF("Err: g_systemData total ThreadCount > MAX_SNIFFER_THREAD_COUNT [%s, %d]\n", __func__, __LINE__);
                    return ERROR_SYS;
                }
            }
            else if (strcmp(iter->name.GetString(), "server") == 0)
            {
                g_systemData.m_serverUrl = iter->value.GetString();
                DEBUG_PRINTF("server %s\n", g_systemData.m_serverUrl.c_str());
            }
            else if (strcmp(iter->name.GetString(), "routermac") == 0)
            {
                _routermac = iter->value.GetString();
                sscanf(_routermac.c_str(), "%2x:%2x:%2x:%2x:%2x:%2x", g_routermac, g_routermac + 1, g_routermac + 2, g_routermac + 3, g_routermac + 4, g_routermac + 5);
                DEBUG_PRINTF("routermac %s\n", _routermac.c_str());
            }
            else if (strcmp(iter->name.GetString(), "if_ether_sender") == 0)
            {
                //DEBUG_PRINTF("aaa %s\n", iter->name.GetString());
                const rapidjson::Value &node = iter->value;
                for (rapidjson::Value::ConstMemberIterator iter2 = node.MemberBegin(); iter2 != node.MemberEnd(); ++iter2)
                {
                    if (strcmp(iter2->name.GetString(), "name") == 0)
                    {
                        _if_ether_sender_name = iter2->value.GetString();
                        DEBUG_PRINTF("if_ether_sender name %s\n", _if_ether_sender_name.c_str());
                    }
                    else if (strcmp(iter2->name.GetString(), "mac") == 0)
                    {
                        _if_ether_sender_mac = iter2->value.GetString();
                        DEBUG_PRINTF("if_ether_sender mac %s\n", _if_ether_sender_mac.c_str());
                    }
                }
            }
            else if (strcmp(iter->name.GetString(), "if_ether_sniffer") == 0)
            {
                const rapidjson::Value &node = iter->value;
                for (rapidjson::Value::ConstValueIterator v_iter = node.Begin(); v_iter != node.End(); ++v_iter)
                {
                    const rapidjson::Value &field = *v_iter;
                    for (rapidjson::Value::ConstMemberIterator iter3 = field.MemberBegin(); iter3 != field.MemberEnd(); ++iter3) // kf对
                    {
                        _if_ether_sniffer_set.push_back(iter3->value.GetString());
                        DEBUG_PRINTF("if_ether_sniffer name %s\n", iter3->value.GetString());
                    }
                }
            }
            else if (strcmp(iter->name.GetString(), "dns_location_server") == 0)
            {
                _dns_location_server = iter->value.GetString();
                //sscanf(_dns_location_server.c_str(),"%uhh.%uhh.%uhh.%uhh",&g_dns_location_server[3],&g_dns_location_server[2],&g_dns_location_server[1],&g_dns_location_server[0]);
                sscanf(_dns_location_server.c_str(), "%d.%d.%d.%d", &g_dns_location_server[0], &g_dns_location_server[1], &g_dns_location_server[2], &g_dns_location_server[3]);
                DEBUG_PRINTF("dns_location_server %s\n", _dns_location_server.c_str());
            }
        }

        int n = 0;
        for (std::vector<std::string>::iterator iter4 = _if_ether_sniffer_set.begin(); iter4 != _if_ether_sniffer_set.end(); ++iter4)
        {
            CDeviceData *dev = new CDeviceData();
            dev->m_ID = n++;
            dev->m_routerMac = _routermac;
            dev->m_sendNetworkCard.m_name = _if_ether_sender_name;
            dev->m_sendNetworkCard.m_mac = _if_ether_sender_mac;
            dev->m_snifferNetworkCard.m_name = *iter4;
            dev->m_snifferNetworkCard.m_statInfo.matchRulePacketCount = 0;
            dev->m_snifferNetworkCard.m_statInfo.totalPacketCount = 0;
            dev->m_snifferNetworkCard.m_statInfo.traffic = 0.00;
            g_systemData.m_deviceDataSet.push_back(dev);
            DEBUG_PRINTF("dev.m_ID = %d\n", dev->m_ID);
        }

        if (n > MAX_SNIFFER_NC_COUNT)
        {
            RUN_PRINTF("Err: Sniffer Network Card Count > MAX_SNIFFER_NC_COUNT [%s, %d]\n", __func__, __LINE__);
            return ERROR_SYS;
        }
    }

    DEBUG_PRINTF("-- init_eth end --\n");

    return RETURN_OK;
}

int SaveGetControl(char *json)
{
    std::string _routermac;
    std::string _if_ether_sender_name;
    std::string _if_ether_sender_mac;
    std::vector<std::string> _if_ether_sniffer_set;

    rapidjson::Document document;

    u_long allFuzzyWordCount = 0;

    if (document.Parse(json).HasParseError())
    {
        return ERROR_FAIL;
    }

    DEBUG_PRINTF("-- get_control --\n");

    if (document.HasMember("num"))
    {
        g_domainRuleNode.num = document["num"].GetInt();
        DEBUG_PRINTF("num %d\n", g_domainRuleNode.num);
    }

    if (document.HasMember("pointid"))
    {
        g_domainRuleNode.pointid = document["pointid"].GetString();
        DEBUG_PRINTF("pointid %s\n", g_domainRuleNode.pointid.c_str());
    }

    if (document.HasMember("data"))
    {
        const rapidjson::Value &data_json = document["data"];
        for (rapidjson::Value::ConstValueIterator v_iter = data_json.Begin(); v_iter != data_json.End(); ++v_iter)
        {
            CData data;

            const rapidjson::Value &field = *v_iter;
            for (rapidjson::Value::ConstMemberIterator iter = field.MemberBegin(); iter != field.MemberEnd(); ++iter)
            {
                //DEBUG_PRINTF("data: [%s]\n", iter->name.GetString());

                if (strcmp(iter->name.GetString(), "exact") == 0)
                {
                    data.exact = iter->value.GetString();
                    DEBUG_PRINTF("exact %s\n", data.exact.c_str());
                }
                else if (strcmp(iter->name.GetString(), "fuzzy") == 0)
                {
                    data.fuzzy = iter->value.GetString();
                    //DEBUG_PRINTF("fuzzy %s\n", data.fuzzy.c_str());
                }
                else if (strcmp(iter->name.GetString(), "host") == 0)
                {
                    data.host = iter->value.GetString();
                    //DEBUG_PRINTF("host %s\n", data.host.c_str());
                }
                else if (strcmp(iter->name.GetString(), "objectid") == 0)
                {
                    data.objectid = iter->value.GetString();
                    //DEBUG_PRINTF("objectid %s\n", data.objectid.c_str());
                }
                else if (strcmp(iter->name.GetString(), "pushrate") == 0)
                {
                    data.pushrate = iter->value.GetInt();
                    //DEBUG_PRINTF("pushrate %d\n", data.pushrate);
                }
                else if (strcmp(iter->name.GetString(), "ratekey") == 0)
                {
                    data.ratekey = iter->value.GetString();
                    //DEBUG_PRINTF("ratekey %d\n", data.ratekey);
                }
                else if (strcmp(iter->name.GetString(), "urlaccord") == 0)
                {
                    data.urlaccord = iter->value.GetString();
                    //trim(data.urlaccord);
                    data.split(data.urlaccord, ",", 0);

                    //for (vector<string>::iterator it = data.urlaccordSet.begin(); it != data.urlaccordSet.end(); ++it)
                    //{
                    //    printf("test: [%s]\n", it->c_str());
                    //}

                    //DEBUG_PRINTF("urlaccord %s\n", data.urlaccord.c_str());
                }
                else if (strcmp(iter->name.GetString(), "urlfilter") == 0)
                {
                    data.urlfilter = iter->value.GetString();
                    //data.urlfilter = trim(data.urlfilter);
                    data.split(data.urlfilter, ",", 1);

                    //for (vector<string>::iterator it = data.urlfilterSet.begin(); it != data.urlfilterSet.end(); ++it)
                    //{
                    //    printf("test: [%s]\n", it->c_str());
                    //}
                    //DEBUG_PRINTF("urlfilter %s\n", data.urlfilter.c_str());
                }
                else if (strcmp(iter->name.GetString(), "account") == 0)
                {
                    const rapidjson::Value &field = iter->value;
                    for (rapidjson::Value::ConstValueIterator w_iter = field.Begin(); w_iter != field.End(); ++w_iter)
                    {
                        CAccount *account = new CAccount();

                        const rapidjson::Value &node = *w_iter;
                        for (rapidjson::Value::ConstMemberIterator iter2 = node.MemberBegin(); iter2 != node.MemberEnd(); ++iter2)
                        {
                            if (strcmp(iter2->name.GetString(), "accountid") == 0)
                            {
                                account->accountid = iter2->value.GetString();
                                //DEBUG_PRINTF("accountid %s\n", account->accountid.c_str());
                            }
                            else if (strcmp(iter2->name.GetString(), "pushcontent") == 0)
                            {
                                account->pushcontent = iter2->value.GetString();
                                //DEBUG_PRINTF("pushcontent %s\n", account->pushcontent.c_str());
                            }
                            else if (strcmp(iter2->name.GetString(), "pushtype") == 0)
                            {
                                account->pushtype = iter2->value.GetString();
                                //DEBUG_PRINTF("pushtype %s\n", account->pushtype.c_str());
                            }
                        }
                        data.account.push_back(account);
                    }
                }
            }

            if (data.exact.empty())
            {
                if (data.host.empty())
                {
                    g_domainRuleNode.fuzzy_NoHost_Data.push_back(data);
                    //printf("rule 1 --- f[%s] h[%s] ---\n", data.fuzzy.c_str(), data.host.c_str());
                    Save2Dictionary(data, allFuzzyWordCount);
                }
                else
                {
                    unordered_map<string, vector<CData>>::iterator it1 = g_domainRuleNode.fuzzy_WithHost_DataMap.find(data.host);
                    if (it1 == g_domainRuleNode.fuzzy_WithHost_DataMap.end())
                    {
                        std::vector<CData> temp;
                        temp.push_back(data);
                        g_domainRuleNode.fuzzy_WithHost_DataMap.insert(std::make_pair(data.host, temp));
                        //printf("rule 2 --- f[%s] h[%s] ---\n", data.fuzzy.c_str(), data.host.c_str());
                    }
                    else
                    {
                        it1->second.push_back(data);
                        //printf("rule 3 --- f[%s] h[%s] ---\n", data.fuzzy.c_str(), data.host.c_str());
                    }
                }
            }
            else
            {
                g_domainRuleNode.exactDataMap.insert(std::make_pair(data.exact, data));
            }
        }
    }

    if (document.HasMember("dns_data"))
    {
        const rapidjson::Value &data_json = document["dns_data"];
        for (rapidjson::Value::ConstValueIterator v_iter = data_json.Begin(); v_iter != data_json.End(); ++v_iter)
        {
            CDnsData *data = new CDnsData();

            const rapidjson::Value &field = *v_iter;
            for (rapidjson::Value::ConstMemberIterator iter = field.MemberBegin(); iter != field.MemberEnd(); ++iter)
            {
                //DEBUG_PRINTF("dns_data: [%s]\n", iter->name.GetString());

                if (strcmp(iter->name.GetString(), "objectid") == 0)
                {
                    data->objectid = iter->value.GetString();
                    //DEBUG_PRINTF("objectid %s\n", data.objectid.c_str());
                }
                else if (strcmp(iter->name.GetString(), "src_domain") == 0)
                {
                    data->src_domain = iter->value.GetString();
                    //DEBUG_PRINTF("src_domain %s\n", data.src_domain.c_str());
                }
                else if (strcmp(iter->name.GetString(), "dst_domain") == 0)
                {
                    data->dst_domain = iter->value.GetString();
                    //DEBUG_PRINTF("dst_domain %s\n", data.dst_domain.c_str());
                }
            }

            g_domainRuleNode.exactDnsDataMap.insert(std::make_pair(data->src_domain, data));
        }
    }

    BuildDictionary();

    TestDictionary();

    DEBUG_PRINTF("-- get_control end --\n");
}

int SaveGetBlacklists(char *json)
{
    rapidjson::Document document;

    u_long blacklistsCount = 0;

    if (document.Parse(json).HasParseError())
    {
        return ERROR_FAIL;
    }

    DEBUG_PRINTF("-- get_blacklists --\n");

    if (document.HasMember("num"))
    {
        blacklistsCount = document["num"].GetInt();
        DEBUG_PRINTF("num %d\n", blacklistsCount);
    }

    if (document.HasMember("blacklists"))
    {
        const rapidjson::Value &blacklists_json = document["blacklists"];
        for (rapidjson::Value::ConstValueIterator v_iter = blacklists_json.Begin(); v_iter != blacklists_json.End(); ++v_iter)
        {
            string User_Name;
            string IP;
            unsigned int u_IP = 0;

            const rapidjson::Value &field = *v_iter;
            for (rapidjson::Value::ConstMemberIterator iter = field.MemberBegin(); iter != field.MemberEnd(); ++iter)
            {
                //DEBUG_PRINTF("blacklists: [%s]\n", iter->name.GetString());

                if (strcmp(iter->name.GetString(), "User_Name") == 0)
                {
                    User_Name = iter->value.GetString();
                    DEBUG_PRINTF("User_Name=%s\n", User_Name.c_str());
                }
                else if (strcmp(iter->name.GetString(), "IP") == 0)
                {
                    IP = iter->value.GetString();
                    DEBUG_PRINTF("IP=%s\n", IP.c_str());
                }
            }

            if (!IP.empty())
            {
                u_IP = ntohl(IPStrToInt(IP.c_str()));
                g_systemData.m_Ip2UserBlacklist.insert(std::make_pair(u_IP, User_Name));
                //DEBUG_PRINTF("u_IP=%d\n", u_IP);
            }

            g_systemData.m_User2IpBlacklist.insert(std::make_pair(User_Name, u_IP));
        }
    }

    DEBUG_PRINTF("-- get_blacklists end --\n");
}

std::string &trim(std::string &s)
{
    if (s.empty())
    {
        return s;
    }

    s.erase(0, s.find_first_not_of(' '));
    s.erase(s.find_last_not_of(' ') + 1);
    return s;
}

void Save2Dictionary(CData &data, u_long &allFuzzyWordCount)
{
    string rule = data.fuzzy;
    rule = replace_all(rule, "[?]", "?");

    std::vector<std::string> words;
    SplitWord(rule, "*", words);

#if 0
    DEBUG_PRINTF("Words: ");
    for (std::vector<std::string>::iterator it = words.begin(); it != words.end(); ++it)
    {
        DEBUG_PRINTF("%s, ", (*it).c_str());
    }
    DEBUG_PRINTF("\n");
#endif

#if 0
    printf("Words:\n");
    for (std::vector<std::string>::iterator it = words.begin(); it != words.end(); ++it)
    {
        CFuzzyData fData;
        fData.m_index = allFuzzyWordCount;
        fData.m_matchRules.push_back(data);

        std::map<std::string, CFuzzyData>::iterator it2 = g_domainRuleNode.fuzzy_Without_Host_DataMap.find(*it);
        if (it2 == g_domainRuleNode.fuzzy_Without_Host_DataMap.end())
        {
            g_domainRuleNode.fuzzy_Without_Host_DataMap.insert(std::make_pair(*it, fData));
        }
        else
        {
            it2->second.m_matchRules.push_back(data);
        }

        g_domainRuleNode.fuzzy_id_Without_Host_DataMap.insert(std::make_pair(allFuzzyWordCount, fData));
        g_domainRuleNode.word_id_2_word_Map.insert(std::make_pair(allFuzzyWordCount, *it));

        allFuzzyWordCount++;

        printf(" %s\n", it->c_str());
    }
#else
    string maxLenWord;
    printf("Words:\n");
    for (std::vector<std::string>::iterator it = words.begin(); it != words.end(); ++it)
    {
        if (maxLenWord.empty())
        {
            maxLenWord = *it;
        }
        else
        {
            if (it->length() > maxLenWord.length())
            {
                maxLenWord = *it;
            }
        }
    }

    CFuzzyData fData;
    fData.m_index = allFuzzyWordCount;
    fData.m_matchRules.push_back(data);

    std::map<std::string, CFuzzyData>::iterator it2 = g_domainRuleNode.fuzzy_Without_Host_DataMap.find(maxLenWord);
    if (it2 == g_domainRuleNode.fuzzy_Without_Host_DataMap.end())
    {
        g_domainRuleNode.fuzzy_Without_Host_DataMap.insert(std::make_pair(maxLenWord, fData));
    }
    else
    {
        it2->second.m_matchRules.push_back(data);
    }

    g_domainRuleNode.fuzzy_id_Without_Host_DataMap.insert(std::make_pair(allFuzzyWordCount, fData));
    g_domainRuleNode.word_id_2_word_Map.insert(std::make_pair(allFuzzyWordCount, maxLenWord));

    allFuzzyWordCount++;

    printf(" %s\n", maxLenWord.c_str());
#endif
}

#if 0
void BuildDictionary()
{
    u_long i = 0;
    FuzzyDoubleArray::key_type **keys;
    keys = new Darts::DoubleArray::key_type*[g_domainRuleNode.fuzzy_Without_Host_DataMap.size()];
    //CFuzzyData *pVals = new CFuzzyData[g_domainRuleNode.fuzzy_Without_Host_DataMap.size()];
    CFuzzyData **pVals = new CFuzzyData*[g_domainRuleNode.fuzzy_Without_Host_DataMap.size()];

    for (std::map<std::string, CFuzzyData>::iterator it = g_domainRuleNode.fuzzy_Without_Host_DataMap.begin();
          it != g_domainRuleNode.fuzzy_Without_Host_DataMap.end(); ++it)
    {
        keys[i] = new Darts::DoubleArray::key_type[MAX_KEY_WORD_LEN];
        *pVals = new CFuzzyData();
        strcpy(keys[i], it->first.c_str());
        *pVals[i] = it->second;
        i++;
    }

    try
    {
        g_domainRuleNode.m_dictionary.build(g_domainRuleNode.fuzzy_Without_Host_DataMap.size(), keys, NULL, pVals);
    }
    catch (Darts::Exception ex)
    {
        std::cout << e.what() << std::endl;
        exit(-1);
    }
}
#else
void BuildDictionary()
{
    std::vector<const char *> keys(g_domainRuleNode.fuzzy_Without_Host_DataMap.size());
    std::vector<int> values(g_domainRuleNode.fuzzy_Without_Host_DataMap.size());

    std::size_t key_id = 0;
    for (std::map<std::string, CFuzzyData>::iterator it = g_domainRuleNode.fuzzy_Without_Host_DataMap.begin();
         it != g_domainRuleNode.fuzzy_Without_Host_DataMap.end();
         ++it, ++key_id)
    {
        keys[key_id] = it->first.c_str();
        values[key_id] = it->second.m_index;
    }

    g_domainRuleNode.m_dictionary.build(keys.size(), &keys[0], NULL, &values[0]);
}
#endif

void TestDictionary()
{
    float time_use = 0;
    struct timeval start;
    struct timeval end;         //struct timezone tz; //后面有说明
    gettimeofday(&start, NULL); //gettimeofday(&start,&tz);结果一样

    Darts::DoubleArray::result_pair_type results[MAX_DIC_WORD_NUM_RESULTS];

    //char key[] = "/s/blog_6b0e6a8d0102xbbe.html";
    std::string key = "/s/blog_6b0e6a8d0102xbbe.html";

    int url_len = key.length();
    const char *pData = key.c_str();
    int i;
    for (i = 0; i < url_len; i++)
    {
        //string sub_url = key.substr(i, url_len - i);

        std::size_t num_results = g_domainRuleNode.m_dictionary.commonPrefixSearch(
            pData, results, MAX_DIC_WORD_NUM_RESULTS);

        //printf("~~~~~~TestDictionary~~~~~~\nkey=%s, num_results=%d\n", pData, num_results);
        //for (std::size_t i = 0; i < (num_results < MAX_DIC_WORD_NUM_RESULTS ? num_results:MAX_DIC_WORD_NUM_RESULTS); i++)
        //{
        //    printf("i%d=%d, %s\n", i, results[i].value, g_domainRuleNode.word_id_2_word_Map[results[i].value].c_str());
        //}
        //printf("~~~~~~TestDictionary~~~~~~\n");
        pData++;
    }

    gettimeofday(&end, NULL);
    time_use = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec); //微秒
    printf("TestDictionary(): i=%d, time_use=%fus\n", i, time_use);
}

void SplitWord(std::string str, const std::string &pattern, std::vector<std::string> &words)
{
    std::string::size_type pos;

    char &tailChar = str.back();

    if (tailChar != '*')
    {
        str += pattern; //扩展字符串以方便操作
    }

    int size = str.size();

    for (int i = 0; i < size; i++)
    {
        pos = str.find(pattern, i);
        if (pos < size)
        {
            std::string s = str.substr(i, pos - i);
            if (!s.empty())
            {
                words.push_back(s);
            }
            i = pos + pattern.size() - 1;
        }
    }
    return;
}

int StatInfoThread()
{
    while (g_systemExit == 0)
    {
        CURL *curl;
        CURLcode res;
        char url[5120];
        std::string jsonInfo;

        g_ss1.str("");
        g_ss1.clear();

        curl = curl_easy_init();

        if (curl)
        {
            //"api/get_control?pointid=%s&sign=%s&version=%s"

            jsonInfo = "";

            struct MemoryStruct chunk;

            chunk.memory = (char *)malloc(1); /* will be grown as needed by the realloc above */
            chunk.size = 0;                   /* no data at this point */

            std::stringstream ss_temp;
            ss_temp << REST_API_URL_BASE << "api/push_count?pointid=" << g_systemData.m_pointid << "&sign=" << g_systemData.m_sign << "&version=" << g_systemData.m_version;
            std::string str_full_url;
            ss_temp >> str_full_url;

#ifdef DEBUG_INFO_PRINTF_FLAG
            cout << str_full_url << endl;
#endif

            curl_easy_setopt(curl, CURLOPT_URL, str_full_url.c_str());

            // 设置http发送的内容类型为JSON
            curl_slist *plist = curl_slist_append(NULL,
                                                  "Content-Type:application/json;charset=UTF-8");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, plist);

            BuildStatInfo(jsonInfo);

            //#ifdef DEBUG_INFO_PRINTF_FLAG
            char szBuf[256] = {0};
            time_t timer = time(NULL);
            strftime(szBuf, sizeof(szBuf), "%Y-%m-%d %H:%M:%S", localtime(&timer));

            RUN_PRINTF("StatInfo: [%s] [%s]\n", szBuf, jsonInfo.c_str());
            //#endif

            // 设置要POST的JSON数据
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonInfo.c_str());
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

            //DEBUG_PRINTF("curl_easy_perform 1\n");
            CURLcode code = curl_easy_perform(curl);
            //DEBUG_PRINTF("curl_easy_perform 2\n");

            if (code == CURLE_OK)
            {
                //DEBUG_PRINTF("[%s]\n", chunk.memory);

                rapidjson::Document document;

                if (document.Parse(chunk.memory).HasParseError())
                {
                    goto STAT_INFO_ERR;
                }
                else
                {
                    if (document.HasMember("code"))
                    {
                        int code = document["code"].GetInt();
                        //DEBUG_PRINTF("code %d\n", code);
                        if (code == 0)
                        {
                            //清除数据
                            ClearStatInfo();
                        }
                    }
                }

                int i = 0;

#ifdef DEBUG_INFO_PRINTF_FLAG

                while (i++ < 60 && g_systemExit == 0)
                {
                    sleep(1);
                }

#else
                //每60*60秒上报一次
                while (i++ < 60 * 60 && g_systemExit == 0)
                {
                    sleep(1);
                }
#endif

                curl_easy_cleanup(curl);
                free(chunk.memory);

                continue;
            }
            else
            {
                RUN_PRINTF("curl_easy_perform return %d\n", code);
            }

        STAT_INFO_ERR:

            curl_easy_cleanup(curl);
            free(chunk.memory);
        }

        //错误,过60*60秒重试
        int j = 0;
        while (j++ < 60 * 60 && g_systemExit == 0)
        {
            sleep(1);
        }
    }

    return 0;
}

int BuildStatInfo(std::string &json)
{
    rapidjson::StringBuffer strBuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strBuf);

    writer.StartObject();

    writer.Key("data");
    writer.StartArray();

    for (unordered_map<string, CData>::const_iterator it1 = g_domainRuleNode.exactDataMap.begin();
         it1 != g_domainRuleNode.exactDataMap.end(); ++it1)
    {
        for (std::vector<CAccount *>::const_iterator it2 = it1->second.account.begin();
             it2 != it1->second.account.end(); ++it2)
        {
            writer.StartObject();

            writer.Key("objectid");
            writer.String(it1->second.objectid.c_str());
            writer.Key("accountid");
            writer.String((*it2)->accountid.c_str());
            writer.Key("count");
            writer.Int64((*it2)->pushCount);

            writer.EndObject();
        }
    }

    for (unordered_map<string, vector<CData>>::const_iterator it3 = g_domainRuleNode.fuzzy_WithHost_DataMap.begin();
         it3 != g_domainRuleNode.fuzzy_WithHost_DataMap.end(); ++it3)
    {
        for (vector<CData>::const_iterator it4 = it3->second.begin();
             it4 != it3->second.end(); ++it4)
        {
            for (std::vector<CAccount *>::const_iterator it5 = it4->account.begin();
                 it5 != it4->account.end(); ++it5)
            {
                writer.StartObject();

                writer.Key("objectid");
                writer.String(it4->objectid.c_str());
                writer.Key("accountid");
                writer.String((*it5)->accountid.c_str());
                writer.Key("count");
                writer.Int64((*it5)->pushCount);

                writer.EndObject();
            }
        }
    }

    for (unordered_map<int, CFuzzyData>::const_iterator it03_1 = g_domainRuleNode.fuzzy_id_Without_Host_DataMap.begin();
         it03_1 != g_domainRuleNode.fuzzy_id_Without_Host_DataMap.end(); ++it03_1)
    {
        const CFuzzyData &fuzzyData = it03_1->second;
        for (std::vector<CData>::const_iterator it03_2 = fuzzyData.m_matchRules.begin(); it03_2 != fuzzyData.m_matchRules.end(); ++it03_2)
        {
            for (std::vector<CAccount *>::const_iterator it03_3 = it03_2->account.begin();
                 it03_3 != it03_2->account.end(); ++it03_3)
            {
                writer.StartObject();

                writer.Key("objectid");
                writer.String(it03_2->objectid.c_str());
                writer.Key("accountid");
                writer.String((*it03_3)->accountid.c_str());
                writer.Key("count");
                writer.Int64((*it03_3)->pushCount);

                writer.EndObject();
            }
        }
    }

    writer.EndArray();

    writer.Key("interfaces");
    writer.StartArray();

    char szBuf[256] = {0};
    time_t timer = time(NULL);
    strftime(szBuf, sizeof(szBuf), "%Y-%m-%d %H:%M:%S", localtime(&timer));

    for (vector<CDeviceData *>::const_iterator it4_1 = g_systemData.m_deviceDataSet.begin(); it4_1 != g_systemData.m_deviceDataSet.end(); ++it4_1)
    {
        writer.StartObject();

        writer.Key("if_name");
        writer.String((*it4_1)->m_snifferNetworkCard.m_name.c_str());
        writer.Key("timestamp");
        (*it4_1)->m_snifferNetworkCard.m_statInfo.timestamp = szBuf;
        writer.String((*it4_1)->m_snifferNetworkCard.m_statInfo.timestamp.c_str());
        writer.Key("match_rule_packet_count");
        writer.Int64((*it4_1)->m_snifferNetworkCard.m_statInfo.matchRulePacketCount);
        writer.Key("total_packet_count");
        writer.Int64((*it4_1)->m_snifferNetworkCard.m_statInfo.totalPacketCount);
        writer.Key("traffic");
        writer.Double((*it4_1)->m_snifferNetworkCard.m_statInfo.traffic);

        writer.EndObject();
    }

    writer.EndArray();

    writer.EndObject();

    json = strBuf.GetString();

    return 0;
}

int ClearStatInfo()
{
    for (unordered_map<string, CData>::iterator it1 = g_domainRuleNode.exactDataMap.begin();
         it1 != g_domainRuleNode.exactDataMap.end(); ++it1)
    {
        for (std::vector<CAccount *>::iterator it2 = it1->second.account.begin();
             it2 != it1->second.account.end(); ++it2)
        {
            (*it2)->pushCount = 0;
        }
    }

    for (unordered_map<string, vector<CData>>::iterator it3 = g_domainRuleNode.fuzzy_WithHost_DataMap.begin();
         it3 != g_domainRuleNode.fuzzy_WithHost_DataMap.end(); ++it3)
    {
        for (vector<CData>::iterator it4 = it3->second.begin();
             it4 != it3->second.end(); ++it4)
        {
            for (std::vector<CAccount *>::iterator it5 = it4->account.begin();
                 it5 != it4->account.end(); ++it5)
            {
                (*it5)->pushCount = 0;
            }
        }
    }

    for (unordered_map<int, CFuzzyData>::iterator it03_1 = g_domainRuleNode.fuzzy_id_Without_Host_DataMap.begin();
         it03_1 != g_domainRuleNode.fuzzy_id_Without_Host_DataMap.end(); ++it03_1)
    {
        CFuzzyData &fuzzyData = it03_1->second;
        for (std::vector<CData>::iterator it03_2 = fuzzyData.m_matchRules.begin(); it03_2 != fuzzyData.m_matchRules.end(); ++it03_2)
        {
            for (std::vector<CAccount *>::iterator it03_3 = it03_2->account.begin();
                 it03_3 != it03_2->account.end(); ++it03_3)
            {
                (*it03_3)->pushCount = 0;
            }
        }
    }

    for (vector<CDeviceData *>::iterator it4_1 = g_systemData.m_deviceDataSet.begin(); it4_1 != g_systemData.m_deviceDataSet.end(); ++it4_1)
    {
        (*it4_1)->m_snifferNetworkCard.m_statInfo.matchRulePacketCount = 0;
        (*it4_1)->m_snifferNetworkCard.m_statInfo.totalPacketCount = 0;
        (*it4_1)->m_snifferNetworkCard.m_statInfo.traffic = 0;
    }

    return 0;
}

int UserIpInfoThread()
{
    while (g_systemExit == 0)
    {
        CURL *curl;
        CURLcode res;
        char url[5120];
        std::string jsonInfo;

        g_ss1.str("");
        g_ss1.clear();

        curl = curl_easy_init();

        if (curl)
        {
            //"api/push_ip_list?pointid=%s&sign=%s&version=%s"

            jsonInfo = "";

            struct MemoryStruct chunk;

            chunk.memory = (char *)malloc(1); /* will be grown as needed by the realloc above */
            chunk.size = 0;                   /* no data at this point */

            std::stringstream ss_temp;
            ss_temp << REST_API_URL_BASE << "api/push_ip_list?pointid=" << g_systemData.m_pointid << "&sign=" << g_systemData.m_sign << "&version=" << g_systemData.m_version;
            std::string str_full_url;
            ss_temp >> str_full_url;

#ifdef DEBUG_INFO_PRINTF_FLAG
            cout << str_full_url << endl;
#endif

            curl_easy_setopt(curl, CURLOPT_URL, str_full_url.c_str());

            // 设置http发送的内容类型为JSON
            curl_slist *plist = curl_slist_append(NULL,
                                                  "Content-Type:application/json;charset=UTF-8");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, plist);

            BuildUserIpInfo(jsonInfo);

            //#ifdef DEBUG_INFO_PRINTF_FLAG
            char szBuf[256] = {0};
            time_t timer = time(NULL);
            strftime(szBuf, sizeof(szBuf), "%Y-%m-%d %H:%M:%S", localtime(&timer));

            RUN_PRINTF("UserIpInfo: [%s] [%s]\n", szBuf, jsonInfo.c_str());
            //#endif

            // 设置要POST的JSON数据
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonInfo.c_str());

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

            CURLcode code = curl_easy_perform(curl);

            if (code == CURLE_OK)
            {
                //DEBUG_PRINTF("[%s]\n", chunk.memory);

                rapidjson::Document document;

                if (document.Parse(chunk.memory).HasParseError())
                {
                    goto STAT_INFO_ERR;
                }
                else
                {
                    if (document.HasMember("code"))
                    {
                        int code = document["code"].GetInt();
                        //DEBUG_PRINTF("code %d\n", code);
                        if (code == 0)
                        {
                        }
                    }
                }

                int i = 0;

#ifdef DEBUG_INFO_PRINTF_FLAG

                while (i++ < 60 && g_systemExit == 0)
                {
                    sleep(1);
                }

#else
                //while (i++ < 3600 && g_systemExit == 0)
                //while (i++ < 60*10 && g_systemExit == 0)
                while (i++ < 60 * 11 && g_systemExit == 0)
                {
                    sleep(1);
                }
#endif

                curl_easy_cleanup(curl);
                free(chunk.memory);

                continue;
            }
            else
            {
                RUN_PRINTF("curl_easy_perform return %d\n", code);
            }

        STAT_INFO_ERR:

            curl_easy_cleanup(curl);
            free(chunk.memory);
        }

        //错误,过60*11秒重试
        int j = 0;
        while (j++ < 60 * 11 && g_systemExit == 0)
        {
            sleep(1);
        }
    }

    return 0;
}

int BuildUserIpInfo(std::string &json)
{
    rapidjson::StringBuffer strBuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strBuf);

    writer.StartObject();

    writer.Key("blacklists");
    writer.StartArray();

    for (unordered_map<string, unsigned int>::const_iterator it1 = g_systemData.m_User2IpBlacklist.begin();
         it1 != g_systemData.m_User2IpBlacklist.end(); ++it1)
    {
        if (it1->second == 0)
        {
            continue;
        }

        char temp[64];
        writer.StartObject();

        writer.Key("User_Name");
        writer.String(it1->first.c_str());
        writer.Key("IP");
        writer.String(IpIntToStr(it1->second, temp));

        writer.EndObject();
    }

    writer.EndArray();

    writer.EndObject();

    json = strBuf.GetString();

    return 0;
}

int VerifyLicense()
{
    int ret = 0;
    CURL *curl;
    CURLcode res;
    int retryTimes = 0;

    do
    {
        if (retryTimes++ > 3)
        {
            return -99;
        }

        curl = curl_easy_init();
        if (curl)
        {
            struct MemoryStruct chunk;
            chunk.memory = (char *)malloc(1); /* will be grown as needed by the realloc above */
            chunk.size = 0;                   /* no data at this point */

            std::stringstream ss;
            ss << "https://116.62.187.105/tp5/public/v0/access/" << g_systemData.m_sign << "/" << g_systemData.m_md5;
            std::string tmp = ss.str();

#ifdef DEBUG_INFO_PRINTF_FLAG
            cout << tmp << endl;
#endif

            curl_easy_setopt(curl, CURLOPT_URL, tmp.c_str());

#ifdef SKIP_PEER_VERIFICATION
            /*
             * If you want to connect to a site who isn't using a certificate that is
             * signed by one of the certs in the CA bundle you have, you can skip the
             * verification of the server's certificate. This makes the connection
             * A LOT LESS SECURE.
             *
             * If you have a CA cert for the server stored someplace else than in the
             * default bundle, then the CURLOPT_CAPATH option might come handy for
             * you.
             */
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

#ifdef SKIP_HOSTNAME_VERIFICATION
            /*
             * If the site you're connecting to uses a different host name that what
             * they have mentioned in their server certificate's commonName (or
             * subjectAltName) fields, libcurl will refuse to connect. You can skip
             * this check, but this will make the connection less secure.
             */
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

            /* Perform the request, res will get the return code */
            res = curl_easy_perform(curl);
            /* Check for errors */
            if (res != CURLE_OK)
            {
                fprintf(stderr, "curl_easy_perform() failed: %s\n",
                        curl_easy_strerror(res));

                /* always cleanup */
                if (curl)
                {
                    curl_easy_cleanup(curl);
                }

                if (chunk.memory)
                {
                    free(chunk.memory);
                }

                continue;
            }
            else
            {
#ifdef DEBUG_INFO_PRINTF_FLAG
                DEBUG_PRINTF("[%s]\n", chunk.memory);
#endif

                rapidjson::Document document;

                if (document.Parse(chunk.memory).HasParseError())
                {
                    /* always cleanup */
                    if (curl)
                    {
                        curl_easy_cleanup(curl);
                    }

                    if (chunk.memory)
                    {
                        free(chunk.memory);
                    }

                    continue;
                }

                if (document.HasMember("error_code"))
                {
                    int error_code = document["error_code"].GetInt();
                    //DEBUG_PRINTF("error_code %d\n", error_code);
                    if (error_code != 0)
                    {
                        /* always cleanup */
                        if (curl)
                        {
                            curl_easy_cleanup(curl);
                        }

                        if (chunk.memory)
                        {
                            free(chunk.memory);
                        }

                        return -99;
                    }
                    else
                    {
                        if (document.HasMember("check"))
                        {
                            std::string check_server = document["check"].GetString();

                            char szBuf[256] = {0};
                            time_t timer = time(NULL);
                            strftime(szBuf, sizeof(szBuf), "%Y-%m-%d %H:", localtime(&timer));

                            std::stringstream ss2;
                            ss2 << g_systemData.m_sign << g_systemData.m_md5 << szBuf;
                            std::string tmp2 = ss2.str();
                            //cout << tmp2 << endl;

                            CryptObject crypt;
                            char *enc_output = crypt.aes_encode(tmp2.c_str(), CryptObject::aeskey);
                            //printf("{%s}\n", enc_output);

                            if (strcmp(check_server.c_str(), enc_output) != 0)
                            {
                                free(enc_output);

                                /* always cleanup */
                                if (curl)
                                {
                                    curl_easy_cleanup(curl);
                                }

                                if (chunk.memory)
                                {
                                    free(chunk.memory);
                                }
                                return -99;
                            }

                            free(enc_output);
                        }
                        else
                        {
                            /* always cleanup */
                            if (curl)
                            {
                                curl_easy_cleanup(curl);
                            }

                            if (chunk.memory)
                            {
                                free(chunk.memory);
                            }

                            return -99;
                        }
                    }

                    /* always cleanup */
                    if (curl)
                    {
                        curl_easy_cleanup(curl);
                    }

                    if (chunk.memory)
                    {
                        free(chunk.memory);
                    }

                    ret = 0;
                    break;
                }
                else
                {
                    /* always cleanup */
                    if (curl)
                    {
                        curl_easy_cleanup(curl);
                    }

                    if (chunk.memory)
                    {
                        free(chunk.memory);
                    }

                    continue;
                }
            }
        }

        sleep(10);

    } while (true);

    return ret;
}

//将整数IP地址转换成字符串IP地址
char *IpIntToStr(const int ip, char *buf)
{
    sprintf(buf, "%u.%u.%u.%u",
            (unsigned char)*((char *)&ip + 0),
            (unsigned char)*((char *)&ip + 1),
            (unsigned char)*((char *)&ip + 2),
            (unsigned char)*((char *)&ip + 3));
    return buf;
}

//IP字符串转32位int数
unsigned int IPStrToInt(const char *ip)
{
    unsigned uResult = 0;
    int nShift = 24;
    int temp = 0;
    const char *pStart = ip;
    const char *pEnd = ip;

    while (*pEnd != '\0')
    {
        while (*pEnd != '.' && *pEnd != '\0')
        {
            pEnd++;
        }
        temp = 0;
        for (pStart; pStart != pEnd; ++pStart)
        {
            temp = temp * 10 + *pStart - '0';
        }

        uResult += temp << nShift;
        nShift -= 8;

        if (*pEnd == '\0')
            break;
        pStart = pEnd + 1;
        pEnd++;
    }

    return uResult;
}

void PrintUser2IpBlacklist(unordered_map<string, unsigned int> &User2IpBlacklist)
{
    for (unordered_map<string, unsigned int>::iterator it = User2IpBlacklist.begin();
         it != User2IpBlacklist.end(); ++it)
    {
        char temp[64];
        printf("=Leo=: PrintUser2IpBlacklist## U=%s, ip=%s, ip=%d\n", it->first.c_str(), IpIntToStr(it->second, temp), it->second);
    }
}

void PrintIp2UserBlacklist(unordered_map<unsigned int, string> &Ip2UserBlacklist)
{
    for (unordered_map<unsigned int, string>::iterator it = Ip2UserBlacklist.begin();
         it != Ip2UserBlacklist.end(); ++it)
    {
        char temp[64];
        printf("=Leo=: PrintIp2UserBlacklist$$ U=%s, ip=%s, ip=%d\n", it->second.c_str(), IpIntToStr(it->first, temp), it->first);
    }
}

/**
 * Convert a DNS label (which may contain pointers) to
 * a string by way of the given destination buffer.
 *
 * \param[in] label     Pointer to the start of the label
 * \param[in] dest      Destination buffer
 * \param[in] dest_size Destination buffer size
 * \param[in] payload   Start of the packet
 * \param[in] end       End of the packet
 * \return dest
 */
u_char *dns_label_to_str(u_char **label, u_char *dest,
                         size_t dest_size,
                         const u_char *payload,
                         const u_char *end)
{
    u_char *tmp, *dst = dest;

    if (!label || !*label || !dest)
        goto err;

    *dest = '\0';
    while (*label < end && **label)
    {
        if (**label & 0xc0)
        { /* Pointer */
            tmp = (u_char *)payload;
            tmp += ntohs(*(uint16_t *)(*label)) & 0x3fff;
            while (tmp < end && *tmp)
            {
                if (dst + *tmp >= dest + dest_size)
                    goto err;
                memcpy(dst, tmp + 1, *tmp);
                dst += *tmp;
                tmp += *tmp + 1;
                if (dst > dest + dest_size)
                    goto err;
                *dst = '.';
                dst++;
            };
            *label += 2;
        }
        else
        { /* Label */
            if ((*label + **label) >= end)
                goto err;
            if (**label + dst >= dest + dest_size)
                goto err;
            memcpy(dst, *label + 1, **label);
            dst += **label;
            if (dst > dest + dest_size)
                goto err;
            *label += **label + 1;
            *dst = '.';
            dst++;
        }
    }

    *(--dst) = '\0';
    return dest;
err:
    if (dest)
        *dest = '\0';
    return dest;
}

/**
 * Skip a DNS label.
 *
 * \param[in] label Pointer to the label
 * \return Pointer to the byte following the label
 */
u_char *skip_dns_label(u_char *label)
{
    u_char *tmp;

    if (!label)
        return NULL;
    if (*label & 0xc0)
        return label + 2;

    tmp = label;
    while (*label)
    {
        tmp += *label + 1;
        label = tmp;
    }
    return label + 1;
}

int GetHostThread()
{
    while (g_systemExit == 0)
    {
        int i = 0;
        char szBuf[256] = {0};
        time_t timer = time(NULL);
        strftime(szBuf, sizeof(szBuf), "%Y-%m-%d %H:%M:%S", localtime(&timer));

        RUN_PRINTF("GetHostThread: [%s]\n", szBuf);
        //遍历DNS中的配置
        for (unordered_map<string, CDnsData *>::iterator it = g_domainRuleNode.exactDnsDataMap.begin();
             it != g_domainRuleNode.exactDnsDataMap.end(); ++it)
        {
            if (it->second->src_domain_ip[0] != 0)
            {
                continue;
            }
            /**
             * 解析后台配置的dns域名转成ip
             *
             **/
            struct hostent *hptr;
            char str[32];
            if ((hptr = gethostbyname(it->first.c_str())) == NULL)
            {
                DEBUG_PRINTF(" gethostbyname error for host:%s\n", it->first.c_str());
                continue;
            }

            if (hptr->h_addrtype == AF_INET)
            {
                printf("%s first address: %s\n", it->first.c_str(),
                       inet_ntop(hptr->h_addrtype, hptr->h_addr, str, sizeof(str)));

                CDnsData *pData = it->second;
                pData->src_domain_ip[0] = (u_char)hptr->h_addr_list[0][0];
                pData->src_domain_ip[1] = (u_char)hptr->h_addr_list[0][1];
                pData->src_domain_ip[2] = (u_char)hptr->h_addr_list[0][2];
                pData->src_domain_ip[3] = (u_char)hptr->h_addr_list[0][3];
            }
        }

#ifdef DEBUG_INFO_PRINTF_FLAG

        while (i++ < 5 * 60 && g_systemExit == 0)
        {
            sleep(1);
        }

#else
        //每20*60秒上报一次
        while (i++ < 5 * 60 && g_systemExit == 0)
        {
            sleep(1);
        }
#endif
    }

    return 0;
}
