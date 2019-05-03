
#ifndef _COMMON_TYPE_H
#define _COMMON_TYPE_H

#include <pcap.h>
#include <unordered_map>
#include <string>

#define SOFTWARE_VERSION        "1.1.0.20180605"

/*返回值*/
#define RETURN_OK          0
#define ERROR_NULL        -1
#define ERROR_NOFIND      -2
#define ERROR_SYS         -3
#define ERROR_LINK        -4
#define ERROR_FAIL        -5
#define ERROR_OUT         -6

#define DEBUG_PRINTF_FLAG           1
#define DEBUG_PRINTF                if(DEBUG_PRINTF_FLAG)printf

#define RUN_PRINTF_FLAG            1
#define RUN_PRINTF          if(RUN_PRINTF_FLAG)printf

#define MAX_SNIFFER_NC_COUNT            10
#define MAX_SNIFFER_THREAD_COUNT        32

#define BUF_SIZE_50                     50

//#define REST_API_URL_BASE       "http://rap2api.taobao.org/app/mock/115822/"
//#define REST_API_URL_BASE       "http://m.xiaojinhui.top:9234/"
//#define REST_API_URL_BASE       "http://m.tuzhuxing.cn:9234/"

#define REST_API_URL_BASE         "http://127.0.0.1:8080/"

//#define REST_API_URL_PARA   "api?cmd=%s&pointid=%s&sign=%s&version=%s"

#define COOKIE_KEY_1          "U2FsdGVk_RATE"
#define COOKIE_KEY_VALUE_1    "U2FsdGVk_RATE=1"

#define MAX_KEY_WORD_LEN                512

#define SKIP_PEER_VERIFICATION
#define SKIP_HOSTNAME_VERIFICATION

#define DNS_UDP_PORT                    53

typedef enum _ThreadProcessType
{
    ThreadProcess_Exact = 0,            //精确匹配线程类型
    ThreadProcess_Fuzzy_WithHost,       //模糊有Host匹配线程类型
    ThreadProcess_Fuzzy_WithOutHost,    //模糊无Host匹配线程类型
} ThreadProcessType;

typedef struct _SYS_RUNTIME_INFO
{
    pcap_t * ghSniff[MAX_SNIFFER_THREAD_COUNT];
    pcap_t * ghSender[MAX_SNIFFER_THREAD_COUNT];

    u_char sendBuffer[MAX_SNIFFER_THREAD_COUNT][10240];

    //memcached_st * ghMem_user = 0;

    std::unordered_map<std::string, std::string> pushTimeMap;        //Key:rule+ip+agent     Value:time
}SYS_RUNTIME_INFO;

struct MemoryStruct {
  char *memory;
  size_t size;
};

typedef struct _STAT_INFO
{
    std::string   timestamp;
    unsigned long matchRulePacketCount;
    unsigned long totalPacketCount;
    double        traffic;
}STAT_INFO;

/**
 * DNS header
 */
struct dnshdr {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed));

/**
 * Basic DNS record types (RFC 1035)
 */
static const char *dns_types[] = {
	"UNKN",  /* Unsupported / Invalid type */
	"A",     /* Host Address */
	"NS",    /* Authorative Name Server */
	"MD",    /* Mail Destination (Obsolete) */
	"MF",    /* Mail Forwarder   (Obsolete) */
	"CNAME", /* Canonical Name */
	"SOA",   /* Start of Authority */
	"MB",    /* Mailbox (Experimental) */
	"MG",    /* Mail Group Member (Experimental) */
	"MR",    /* Mail Rename (Experimental) */
	"NULL",  /* Null Resource Record (Experimental) */
	"WKS",   /* Well Known Service */
	"PTR",   /* Domain Name Pointer */
	"HINFO", /* Host Information */
	"MINFO", /* Mailbox / Mail List Information */
	"MX",    /* Mail Exchange */
	"TXT",   /* Text Strings */
	"AAAA"   /* IPv6 Host Address (RFC 1886) */
};


//编译开关
#define USE_SPINLOCK
//#define USE_COOKIE_FOR_CHECKPUSHRATE                            //使用Cookie判断推送时间
//#define DEBUG_INFO_PRINTF_FLAG                                  //部分调试信息打印

static const std::size_t MAX_DIC_WORD_NUM_RESULTS = 50;         //词典返回的最大Word数

char *IpIntToStr(const int ip, char *buf);
unsigned int IPStrToInt(const char *ip);
void PrintUser2IpBlacklist(std::unordered_map<std::string, unsigned int> &User2IpBlacklist);
void PrintIp2UserBlacklist(std::unordered_map<unsigned int, std::string> &Ip2UserBlacklist);

#endif


