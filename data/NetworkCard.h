
#ifndef _NETWORK_CARD_DATA_H
#define _NETWORK_CARD_DATA_H

#include <string>
#include "../include/common_type.h"

using std::string;

class CNetworkCardData
{
public:
    CNetworkCardData();
    ~CNetworkCardData();

public:
    string m_name;
    string m_mac;

    STAT_INFO m_statInfo;
};

#endif

