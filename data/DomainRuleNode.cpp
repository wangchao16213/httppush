#include "DomainRuleNode.h"

CAccount::CAccount()
{
    pushCount = 0;
}

CAccount::~CAccount()
{
}

CData::CData()
{
}

CData::~CData()
{
}

void CData::split(std::string str, std::string pattern, int type)
{
    std::string::size_type pos;

	str += pattern;//扩展字符串以方便操作
	int size = str.size();

    if (type == 0)
    {
        urlaccordSet.clear();
    }
    else
    {
        urlfilterSet.clear();
    }

	for (int i = 0; i < size; i++)
	{
		pos = str.find(pattern, i);
		if (pos < size)
		{
			std::string s = str.substr(i, pos - i);

            if (type == 0)
            {
                urlaccordSet.push_back(s);
            }
            else
            {
                urlfilterSet.push_back(s);
            }

			i = pos + pattern.size() - 1;
		}
	}
}

CFuzzyData::CFuzzyData()
{
}

CFuzzyData::~CFuzzyData()
{
}

CDomainRuleNode::CDomainRuleNode()
{

}

CDomainRuleNode::~CDomainRuleNode()
{

}

