#ifndef _DOMAIN_NODE_H
#define _DOMAIN_NODE_H

#include "../include/darts.h"
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>

using std::string;
//using std::vector;
using std::map;
using std::cin;
using std::cout;
using std::endl;
using std::unordered_map;

class CAccount
{
public:
	CAccount();
	~CAccount();

public:
	string accountid = "";
	string pushtype = "";
	string replacekey = "";
	string pushcontent = "";

    long pushCount = 0;			//推送次数统计
};

class CData
{
public:
	CData();
	~CData();

    void split(std::string str, std::string pattern, int type);

public:
	string objectid = "";
	string exact = "";
	string fuzzy = "";
    string host = "";
    string urlaccord = "";
	string urlfilter = "";
	//string agentfilter = "";
	//string agentmatch = "";
	//bool isrefer = false;
	int    pushrate = 0;
    string ratekey = "";
    std::vector<CAccount*> account;

public:
    std::vector<string> urlaccordSet;
    std::vector<string> urlfilterSet;

	long count;			//Action次数统计
	//u_long lastTick;		//最后一次执行动作的Tick

public:
    // overload operator==
    bool operator==(const CData& p) {
        return this->objectid == p.objectid && this->exact == p.exact
            && this->fuzzy == p.fuzzy;
    }

    inline friend std::ostream& operator<<(std::ostream& os, CData& p)
    {
        os << "[CData] -> (" << p.objectid << ", " << p.exact << ", " << p.fuzzy << ")";
        return os;
    }
};

// declare hash<Person>
namespace std {
 template <>
 struct hash<CData> {
     std::size_t operator()(const CData& p) const {
      using std::size_t;
      using std::hash;
      using std::string;
      // Compute individual hash values for first,
      // second and third and combine them using XOR
      // and bit shifting:
      return ((hash<string>()(p.objectid)
        ^ (hash<string>()(p.exact) << 1)) >> 1)
        ^ (hash<string>()(p.fuzzy) << 1);
     }
 };
}

class CFuzzyData
{
public:
    CFuzzyData();
    ~CFuzzyData();

public:
	int m_index;                            //关键词索引
	std::vector<CData> m_matchRules;        //模糊匹配规则
};

class CDnsData
{
public:
	CDnsData()
    {
        src_domain_ip[0] = 0;
        src_domain_ip[1] = 0;
        src_domain_ip[2] = 0;
        src_domain_ip[3] = 0;
    }

	~CDnsData()
    {
    }

public:
	string objectid = "";
	string src_domain = "";
    string dst_domain = "";

    int src_domain_ip[4];

public:
    // overload operator==
    bool operator==(const CDnsData& p) {
        return this->objectid == p.objectid && this->src_domain == p.src_domain
            && this->dst_domain == p.dst_domain;
    }

    inline friend std::ostream& operator<<(std::ostream& os, CDnsData& p)
    {
        os << "[CDnsData] -> (" << p.objectid << ", " << p.src_domain << ", " << p.dst_domain << ")";
        return os;
    }
};

// declare hash<Person>
namespace std {
 template <>
 struct hash<CDnsData> {
     std::size_t operator()(const CDnsData& p) const {
      using std::size_t;
      using std::hash;
      using std::string;
      // Compute individual hash values for first,
      // second and third and combine them using XOR
      // and bit shifting:
      return ((hash<string>()(p.objectid)
        ^ (hash<string>()(p.src_domain) << 1)) >> 1)
        ^ (hash<string>()(p.dst_domain) << 1);
     }
 };
}

//typedef Darts::DoubleArrayImpl<void, void, int, void> FuzzyDoubleArray;

class CDomainRuleNode
{
public:
    CDomainRuleNode();
    ~CDomainRuleNode();

public:
    int num;
	string pointid;

    unordered_map<string, CData> exactDataMap;                           //精确匹配规则
    unordered_map<string, std::vector<CData>> fuzzy_WithHost_DataMap;    //模糊匹配&有Host规则
	std::vector<CData> fuzzy_NoHost_Data;                                //模糊匹配&无Host规则
    
    unordered_map<string, CDnsData*> exactDnsDataMap;                     //精确DNS匹配规则

    map<string, CFuzzyData> fuzzy_Without_Host_DataMap;
    unordered_map<int, CFuzzyData> fuzzy_id_Without_Host_DataMap;
    unordered_map<int, string> word_id_2_word_Map;
    Darts::DoubleArray m_dictionary;
};


#endif

