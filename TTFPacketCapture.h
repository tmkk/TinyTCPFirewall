#pragma once

#include <winsock2.h>

class TTFPacketCapture
{
protected:
	SOCKET socket;
	WSADATA wsd;
	unsigned char *buffer;
	bool initialized;
	
public:
	unsigned int localAddr;
	
	TTFPacketCapture();
	~TTFPacketCapture();
	bool open(unsigned int addr);
	bool read(unsigned char *buf, unsigned int &size);
	void close(void);
};
