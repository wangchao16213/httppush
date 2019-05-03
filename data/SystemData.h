
#ifndef _SYSTEM_DATA_H
#define _SYSTEM_DATA_H

#include <vector>
#include <unordered_map>
#include "DeviceData.h"

using std::vector;
using std::unordered_map;

class CSystemData
{
public:
    CSystemData();
    ~CSystemData();

public:
    std::string m_pointid;              //渠道ID
    std::string m_sign;                 //本机唯一标识
    std::string m_version;              //软件版本
    std::string m_serverUrl;            //服务器地址

    std::string m_md5;

    int m_snifferThreadCount;           //精确匹配线程数
    int m_fuzzy_with_host_thread_count; //模糊有Host匹配线程数
    int m_fuzzy_without_host_thread_count;//模糊无Host匹配线程数
    int m_totalThreadCount;             //总线程数

    int m_stat;                         //状态 0表示正常 -1表示异常

    vector<CDeviceData*> m_deviceDataSet;

    int m_radiusAccessPort;             //RADIUS Access 端口 [1645,1812]
    int m_radiusAccountingPort;         //RADIUS Accounting 端口 [1646,1813]
    unordered_map<string, unsigned int> m_User2IpBlacklist;     //黑名单,User到IP映射
    unordered_map<unsigned int, string> m_Ip2UserBlacklist;     //黑名单,IP到User映射
};

#endif

