#ifndef _HTTP_REQUEST_H
#define _HTTP_REQUEST_H

#include <vector>
#include <string>

class HttpRequest
{
public:
	HttpRequest();
	~HttpRequest();

	void Init();
	int ParseData(char* http_data, int thread_index);

    std::string ToString();

	std::vector<std::string> split(std::string str, const std::string &pattern, unsigned long &count, int max_section);

    int drop_useless_packet(char * packet);

public:
	std::string Method;
	std::string Path;
	std::string HttpVersion;

	std::string Host;
	std::string UserAgent;
	std::string Referer;
    std::string Cookie;

	std::string url;
};


#endif
