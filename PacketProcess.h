
#ifndef _PACKET_PROCESS_H
#define _PACKET_PROCESS_H

#include "data/DeviceData.h"
#include "data/DomainRuleNode.h"
#include "HttpRequest.h"
#include <string>
#include "include/common_type.h"


class CPacketProcess
{
public:
    static void BuildDnsAnswer_Type1(struct dnshdr * _dnshdr, u_char * dnsAnswer, u_int udpLen, u_int *pSendDataLength, CDnsData *pDnsData);
    static void BuildDnsAnswer_Type2(struct dnshdr * _dnshdr, u_char * dnsAnswer, u_int udpLen, u_int *pSendDataLength, CDnsData *pDnsData);

    //启动一块网卡的抓包及处理
    static int StartSnifferPacket(const CDeviceData* deviceData);

    static int StartPcap(int thread_index, const CDeviceData* deviceData);

    static void PacketProcess(int thread_index, int this_type_thread_index, int this_type_thread_conut, ThreadProcessType this_thread_type, const CDeviceData* deviceData);

    static int analyzeHTTP(int nc_index, int thread_index, int this_type_thread_index, int this_type_thread_conut, ThreadProcessType this_thread_type, const u_char * packet, HttpRequest &httpReq, const CDeviceData* deviceData);

    static int MatchRulesAndDoAction(int nc_index, int thread_index, ThreadProcessType this_thread_type, struct ether_header *pEther, struct iphdr * pIpHdr, struct tcphdr * pTcpHdr,
									 const HttpRequest &request, const CDeviceData* deviceData);

    static int ActionRand(int min, int max);

    static void DoAction(int nc_index, int thread_index, struct ether_header *pEthSrc, struct iphdr * pIpSrc, struct tcphdr * pTcpSrc,
                         const string &objectid, const string &accountid, const string &pushtype, const string &replacekey, const string &pushcontent,
                         const string &cookie);

    static int inject_302_Location(int nc_index, int thread_index, struct ether_header *pEthSrc, struct iphdr * pIpSrc, struct tcphdr * pTcpSrc, const string &url,
                                   const string &cookie);

    static int inject_200_Content(int nc_index, int thread_index, struct ether_header *pEthSrc, struct iphdr * pIpSrc, struct tcphdr * pTcpSrc, const string &content, const string &pushtype,
                                  const string &cookie);

    static int CheckPushRate(int nc_id, int thread_index, int pushrate, const std::string &ratekey, const std::string rule, u_int ip, const std::string &agent,
                             const std::string &cookie);

    static int CheckFileTypeFilter(const HttpRequest &request);

    static int GetRulesByDictionary(const HttpRequest &request, std::vector<CData> &fuzzy_NoHost_Rules, std::vector<CData>::iterator &it);

    static void MakePushCookie(string &cookie, const string &host, int pushrate);

    static void UdpProcess(struct iphdr* pIpHdr, char * pSendData, u_int *pSendDataLength);
};

string& replace_all(string& str,const string& old_value,const string& new_value);

void ProcessHost4Cookie(std::string &host);

#endif
