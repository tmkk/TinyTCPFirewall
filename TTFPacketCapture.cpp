#include <stdio.h>
#include <ws2tcpip.h>
#include <iptypes.h>
#include "TTFPacketCapture.h"

#define BUFFER_SIZE 65536

TTFPacketCapture::TTFPacketCapture() :
	initialized(false)
{
	buffer = new unsigned char[BUFFER_SIZE];
}

TTFPacketCapture::~TTFPacketCapture()
{
	delete [] buffer;
}

bool TTFPacketCapture::open(unsigned int addr)
{
	if(WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		fprintf(stderr, "Error in WSAStartup\n");
		return false;
	}
	if((socket = WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET)
	{
		fprintf(stderr,"Error in WSASocket\n");
		return false;
	}
	
	if(!addr) {
		char hostname[NI_MAXHOST + 1] = {'\0'};
		if(gethostname(hostname, sizeof(hostname))) {
			fprintf(stderr,"Error in gethostname\n");
			return false;
		}
		addrinfo hint;
		ZeroMemory(&hint, sizeof(hint));
		hint.ai_family = PF_INET;
		hint.ai_flags = AI_CANONNAME;
		addrinfo* res = 0;
		if(getaddrinfo(hostname, 0, &hint, &res)) {
			fprintf(stderr,"Error in getaddrinfo\n");
			return false;
		}
		struct sockaddr_in *sa = (struct sockaddr_in *)(res->ai_addr);
		localAddr = sa->sin_addr.s_addr;
	}
	else localAddr = addr;
	
	SOCKADDR_IN addr_in;
	ZeroMemory(&addr_in, sizeof(addr_in));
	addr_in.sin_addr.s_addr = localAddr;
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = 0;
	if(bind(socket, (SOCKADDR*)&addr_in, sizeof(addr_in)) == SOCKET_ERROR)
	{
		fprintf(stderr,"Error in bind\n");
		return false;
	}
	
	DWORD ret;
	unsigned long optval=1;
	if(WSAIoctl(socket, _WSAIOW(IOC_VENDOR, 1), &optval, sizeof(optval), NULL, 0, &ret, NULL, NULL) == SOCKET_ERROR)
	{
		fprintf(stderr,"Error in WSAIoctl; cannot set socket to promiscuous mode\n");
		return false;
	}
	
	initialized = true;
	return true;
}

bool TTFPacketCapture::read(unsigned char *buf, unsigned int &size)
{
	unsigned long length;
	unsigned long flags = 0;
	WSABUF wsb;
	wsb.buf = (char *)buffer;
	wsb.len = BUFFER_SIZE;
	ZeroMemory(wsb.buf, wsb.len);
	
	if(WSARecv(socket, &wsb, 1, &length, &flags, NULL, NULL) == SOCKET_ERROR)
	{
		fprintf(stderr,"Error in WSARecv\n");
		return false;
	}
	
	size = length > size ? size : length;
	memcpy(buf, buffer, size);
	return true;
}

void TTFPacketCapture::close(void)
{
	if(!initialized) return;
	WSACleanup();
}
