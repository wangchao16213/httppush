#include <sstream>
//#include <iostream>
#include <string.h>
#include "HttpRequest.h"
#include "include/common_type.h"

using std::string;
using std::endl;

HttpRequest::HttpRequest()
{
}

HttpRequest::~HttpRequest()
{
}

void HttpRequest::Init()
{
	Method = "";
	Path = "";
	HttpVersion = "";
	Host = "";
	UserAgent = "";
	Referer = "";
    url = "";
}

extern unsigned long g_splitSize[];

#if 0
int HttpRequest::ParseData(char* pData, int thread_index)
{
	string str(pData);
    bool bFindKey[10] = {false};
	std::vector<std::string> lines = split(str, "\r\n", g_splitSize[0], 15);

	for (int i = 0; i < lines.size(); i++)
	{
		//std::printf("%s\r\n", lines[i].c_str());

		if (i == 0)
		{
			//Method
			std::vector<std::string> words = split(lines[i], " ", g_splitSize[1], 3);

			if (words.size() != 3)
			{
                //printf("words.size() = %d, lines[0]=%s\n", words.size(), lines[i].c_str());
				return -1;
			}

			Method = words[0];
            bFindKey[0] = true;

			if (Method.compare("GET") != 0)
			{
				return -2;
			}

			Path = words[1];
            bFindKey[1] = true;

			HttpVersion = words[2];
            bFindKey[2] = true;

			if (HttpVersion.compare("HTTP/1.1") != 0)
			{
				return -3;
			}
		}
		else
		{
			std::vector<std::string> words = split(lines[i], ": ", g_splitSize[2], 2);

            if (words.size() != 2)
            {
                return -1;
            }

			if (words[0].compare("Host") == 0)
			{
				Host = words[1];
                bFindKey[3] = true;
			}
			else if (words[0].compare("User-Agent") == 0)
			{
				UserAgent = words[1];
                bFindKey[4] = true;
			}
			//else if (words[0].compare("Referer") == 0)
			//{
			//	Referer = words[1];
            //    bFindKey[5] = true;
			//}
		}

        if (bFindKey[0] && bFindKey[1] && bFindKey[2] && bFindKey[3] && bFindKey[4])
        {
            break;
        }
    }

    if (!(bFindKey[0] && bFindKey[1] && bFindKey[2] && bFindKey[3]))
    {
        return -5;
    }

	url = Host + Path;

	//LOG4CXX_INFO(logger, "url = " + url);

	return 0;
}

#else

typedef struct _http_info_
{
    char                     * cooki;                   /*cookie*/
    char                     * refer;                   /*refer*/
    char                     * uri;                     /*uri*/
    char                     * UA;                      /*UA*/
    char                     * host;                    /*����*/
    char                     * gz;
    unsigned long            ip;                        /*ip*/                                 
}http_info;

http_info g_head[MAX_SNIFFER_THREAD_COUNT];

int HttpRequest::ParseData(char* pData, int thread_index)
{
    #if 0
    char buf0[2000];
    char buf1[2000];
    char buf2[2000];
    char buf3[2000];
    char 			  **host = (char**)&buf0;
    char 			  **path = (char**)&buf1;
    char 			  **user_agent = (char**)&buf2;
    char 			  **referer = (char**)&buf3;
    #else
    //char data_buf[3000];
    char 			  **host = &(g_head[thread_index].host);
    char 			  **path = &(g_head[thread_index].uri);
    char 			  **user_agent = &(g_head[thread_index].UA);
    char 			  **referer = &(g_head[thread_index].refer);
    char 			  **cookie  = &(g_head[thread_index].cooki);
    char* http_data = pData;
    *referer = 0;
    //printf("Data len: %d\n", strlen(pData));
    //strcpy(data_buf, pData);
    #endif

    int					ret, b_index;

	if(NULL == http_data)
    {
        return ERROR_NULL;
    }
	
    if((*http_data == 'G') && ((*(http_data + 1) == 'E')) || ((*http_data=='P') && (*(http_data + 1) == 'O'))) 
	{
		// 零时指针变量
		char *tmp;

		tmp = http_data;
		// 特殊参数
		*path = strchr(tmp, '/');
		if(!*path) 
		{
			return ERROR_FAIL;
		}

		tmp = strchr(*path, ' ');
		if(tmp) 
		{
			/*丢弃无用包*/
            //tmp[0] = '\0';
            //tmp++;

			ret = drop_useless_packet(tmp);
			if(ret != RETURN_OK)
			{
				//DEBUG_PRINTF("drop_useless_packet fail ret = %d, LINE = %d, FUN = %s, FILE = %s\n", \
				//	ret, __LINE__, __func__, __FILE__);
				return ret;
			}

			tmp[0] = '\0';
			tmp++;
		} 
		else 
		{
			return ERROR_FAIL;
		}

		tmp = strchr(tmp, '\r');
		b_index = -1;
		// 搜索所有特定char并提取相关key的value
		while (tmp)
		{
			tmp[0] = '\0';
			tmp += 2;

            /*
			if((*host)&&(strcmp(*path, "/favicon.ico")))
			{
				if((strlen(*host) > 100))
				{
					return ERROR_FAIL;
				}
				

				ret = hash_rule_value_get(a_num, *host, &b_rule);
				if(ret != RETURN_OK)
				{
					DEBUG_PRINTF("hash_json_value_get fail ret = %d, line = %d, fun = %s, file = %s\n", \
						ret, __LINE__, __func__, __FILE__);
					return ret;
				}
				
				b_index = pkt_rule_host_uri(*path, *host, b_rule);
				if(b_index < 0)
				{
					DEBUG_PRINTF("pkt_rule_host_uri fail ret = %d, line = %d, fun = %s, file = %s\n", \
						b_index, __LINE__, __func__, __FILE__);
					return ERROR_NOFIND;
				}
            } 
            */ 
			
			// switch字符char之后的一位
			switch (tmp[0])
			{
				case 'H':
				{
					// 精确比较
					if((tmp[1] == 'o')&&(tmp[2] == 's')&&(tmp[3] == 't')&&(tmp[4] == ':'))
					{
						*host = tmp + 6;                        
					}
					//b_static++;
					break;
				}
				case 'U':
				{
					if((tmp[1] == 's')&&(tmp[3] == 'r')&&(tmp[5] == 'A')&&(tmp[10] == ':'))
					{
						*user_agent = tmp + 12;
					}
					break;
				}
				case 'R':
				{
					if((tmp[1] == 'e')&&(tmp[3] == 'e')&&(tmp[5] == 'e')&&(tmp[7] == ':'))
					{
						*referer = tmp + 9;
					}
					else if((tmp[1] == 'a')&&(tmp[3] == 'g')&&(tmp[4] == 'e')&&(tmp[5] == ':'))
					{
						return ERROR_FAIL;
					}
					break;
				}
				case 'C':
				{
					if((tmp[1] == 'o')&&(tmp[3] == 'k')&&(tmp[5] == 'e')&&(tmp[6] == ':'))
					{
						*cookie = tmp + 8;
					}
					break;
				}
                /*
				case 'A':
				{
					if((tmp[1] == 'c')&&(tmp[5] == 't')&&(tmp[7] == 'E')&&(tmp[15] == ':'))
					{
						*gzip = tmp + 17;
					}
					break;
				}
				*/	
			}

			tmp = strchr(tmp, '\r');
		}



        /* 
        if(b_index < 0)
		{
			return ERROR_NOFIND;
		}
		ret = pkt_rule_parse(* a_head, a_rep_info, b_rule, a_num, b_index);
		if(ret != RETURN_OK)
		{
			DEBUG_PRINTF("pkt_rule_parse fail ret = %d, line = %d, fun = %s, file = %s\n", ret, __LINE__, \
				__func__, __FILE__);
			return ret;
        } 
        */ 

        //printf("~~path=%s\n",*path);
        //printf("~~host=%s\n",*host);

        if (*path) 
        {
            Path = *path;
        }

        if (*host) 
        {
            Host = *host;
        }

        if (*user_agent) 
        {
            UserAgent = *user_agent;
        }

        if (*referer) 
        {
            Referer = *referer;
            //printf("~~referer=%s\n",*referer);
        }

        if (*cookie) 
        {
            Cookie = *cookie;
            //printf("~~cookie=%s\n",*cookie);
        }

        url = Host + Path;

		return RETURN_OK;
    }
    else 
	{
		return ERROR_FAIL;
	}

	return RETURN_OK;
}
#endif

int HttpRequest::drop_useless_packet(char * packet)
{
	if(packet[-4] == '.')
	{
		/*css html htm jpg gif png*/
        if((packet[-3] == 'p')&&(packet[-2] == 'n')&&(packet[-1] == 'g'))
		{
			return ERROR_FAIL;
		}

		if((packet[-3] == 'j')&&(packet[-2] == 'p')&&(packet[-1] == 'g'))
		{
			return ERROR_FAIL;
		}

		if((packet[-3] == 'g')&&(packet[-2] == 'i')&&(packet[-1] == 'f'))
		{
			return ERROR_FAIL;
		}

        if((packet[-3] == 'c')&&(packet[-2] == 's')&&(packet[-1] == 's'))
		{
			return ERROR_FAIL;
		}

        if((packet[-3] == 'x')&&(packet[-2] == 'm')&&(packet[-1] == 'l'))
		{
			return ERROR_FAIL;
		}

        if((packet[-3] == 'm')&&(packet[-2] == 'p')&&(packet[-1] == '4'))
		{
			return ERROR_FAIL;
		}

        if((packet[-3] == 'm')&&(packet[-2] == 'p')&&(packet[-1] == '3'))
		{
			return ERROR_FAIL;
		}

        if((packet[-3] == 'z')&&(packet[-2] == 'i')&&(packet[-1] == 'p'))
		{
			return ERROR_FAIL;
		}

        if((packet[-3] == 'r')&&(packet[-2] == 'a')&&(packet[-1] == 'r'))
		{
			return ERROR_FAIL;
		}
	}
    else if (packet[-5] == '.') 
    {
        if((packet[-4] == 'w')&&(packet[-3] == 'e')&&(packet[-2] == 'b')&&(packet[-1] == 'p'))
		{
			return ERROR_FAIL;
		}

        if((packet[-4] == 'j')&&(packet[-3] == 'p')&&(packet[-2] == 'e')&&(packet[-1] == 'g'))
		{
			return ERROR_FAIL;
		}

        if((packet[-4] == 'j')&&(packet[-3] == 's')&&(packet[-2] == 'o')&&(packet[-1] == 'n'))
		{
			return ERROR_FAIL;
		}
    }

#if 0
	if((packet[-3] == 'h')&&(packet[-2] != 't')&&(packet[-1] != 'm'))
	{
		return ERROR_FAIL;
	}

	if((packet[-3] == 'c')&&(packet[-2] != 's')&&(packet[-1] != 's'))
	{
		return ERROR_FAIL;
	}

	if((packet[-3] == 't')&&(packet[-2] != 'm')&&(packet[-1] != 'l'))
	{
		return ERROR_FAIL;
	}
#endif
	return RETURN_OK;
}

//字符串分割函数
std::vector<std::string> HttpRequest::split(std::string str, const std::string &pattern, unsigned long &count, int max_section)
{
	std::string::size_type pos;
	std::vector<std::string> result;
	str += pattern;//扩展字符串以方便操作
	int size = str.size();

    count = 0;

	for (int i = 0; i<size; i++)
	{
		pos = str.find(pattern, i);
		if (pos<size)
		{
			std::string s = str.substr(i, pos - i);
			result.push_back(s);
			i = pos + pattern.size() - 1;
            count++;

            if (count >= max_section)
            {
                //break;
            }
        }
	}
	return result;
}

std::string HttpRequest::ToString()
{
    std::stringstream ss;
    ss << endl\
       << "== Http Request ==" << endl\
       << " HttpVersion = " << HttpVersion <<endl\
       << " Method      = " << Method << endl\
       << " Host        = " << Host << endl\
       << " Path        = " << Path << endl\
       << " UserAgent   = " << UserAgent << endl\
       << " Referer     = " << Referer << endl\
       << " url         = " << url << endl;

    std::string out = ss.str();
    return out;
}
