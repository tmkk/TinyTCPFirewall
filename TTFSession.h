#pragma once

#include <sys/time.h>
#include <string>
#include <tr1/memory>

class TTFSession
{
public:
	const unsigned int localAddr;
	const unsigned int localPort;
	const unsigned int remoteAddr;
	const unsigned int remotePort;
	const std::string processName;
	
	unsigned long long bytesSent;
	unsigned long long bytesReceived;
	double lastChecked;

protected:
	struct timeval monitoringSince;

public:
	TTFSession(unsigned int lAddr, unsigned int lPort, unsigned int rAddr, unsigned int rPort, std::string& pName);
	
	double averageUpSpeed(void);
	double averageDownSpeed(void);
	double timeElapsed(void);
	void commitPacket(unsigned char *data);
	void disconnect(void);
	void status(void);
};

typedef std::tr1::shared_ptr<TTFSession> PTTFSession;
