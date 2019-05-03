
#ifndef _DEVICE_DATA_H
#define _DEVICE_DATA_H

#include <string>
#include "NetworkCard.h"

using std::string;

class CDeviceData
{
public:
    CDeviceData();
    ~CDeviceData();

public:
    int m_ID;       //序号ID，用于索引
    CNetworkCardData m_snifferNetworkCard;
    CNetworkCardData m_sendNetworkCard;
    string m_routerMac;
    //int m_snifferThreadCount;
};

#endif

