#include <stdio.h>
#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#endif
#include "TTFSession.h"
#include "log.h"

typedef struct
{
	unsigned char  verhead;
	unsigned char  tos;
	unsigned short len;
	unsigned short id;
	unsigned short frag;
	unsigned char  ttl;
	unsigned char  prot;
	unsigned short chksum;
	unsigned int srcip;
	unsigned int dstip;
	unsigned char  data[0];
} IPHeader;

TTFSession::TTFSession(unsigned int lAddr, unsigned int lPort, unsigned int rAddr, unsigned int rPort, std::string& pName) :
	localAddr(lAddr), localPort(lPort), remoteAddr(rAddr), remotePort(rPort), processName(pName),
	bytesSent(0), bytesReceived(0), lastChecked(0)
{
	gettimeofday(&monitoringSince,NULL);
}

double TTFSession::averageUpSpeed(void)
{
	struct timeval current;
	gettimeofday(&current, NULL);
	double diff = (current.tv_sec - monitoringSince.tv_sec) + (current.tv_usec - monitoringSince.tv_usec) * 1e-6;
	
	return (double)bytesSent / diff;
}

double TTFSession::averageDownSpeed(void)
{
	struct timeval current;
	gettimeofday(&current, NULL);
	double diff = (current.tv_sec - monitoringSince.tv_sec) + (current.tv_usec - monitoringSince.tv_usec) * 1e-6;
	
	return (double)bytesReceived / diff;
}

double TTFSession::timeElapsed(void)
{
	struct timeval current;
	gettimeofday(&current, NULL);
	return (current.tv_sec - monitoringSince.tv_sec) + (current.tv_usec - monitoringSince.tv_usec) * 1e-6;
}

void TTFSession::commitPacket(unsigned char *data)
{
	if(!data) return;
	IPHeader *header = (IPHeader *)data;
	if(header->srcip == localAddr)
		bytesSent += ntohs(header->len);
	else if(header->dstip == localAddr)
		bytesReceived += ntohs(header->len);
}

void TTFSession::disconnect()
{
#ifdef _WIN32
	MIB_TCPROW session;
	session.dwLocalAddr = localAddr;
	session.dwLocalPort = htons(localPort);
	session.dwRemoteAddr = remoteAddr;
	session.dwRemotePort = htons(remotePort);
	session.dwState = MIB_TCP_STATE_DELETE_TCB;
	SetTcpEntry(&session);
#endif
	log_dated_printf(" (%s)\n    Closed connection %d.%d.%d.%d:%d <--> %d.%d.%d.%d:%d\n",processName.c_str(),localAddr&0xff,(localAddr >> 8)&0xff,(localAddr >> 16)&0xff,(localAddr >> 24)&0xff,localPort,remoteAddr&0xff,(remoteAddr >> 8)&0xff,(remoteAddr >> 16)&0xff,(remoteAddr >> 24)&0xff,remotePort);
}

void TTFSession::status()
{
	fprintf(stderr,"* %d.%d.%d.%d:%d <--> %d.%d.%d.%d:%d [%s]\n",localAddr&0xff,(localAddr >> 8)&0xff,(localAddr >> 16)&0xff,(localAddr >> 24)&0xff,localPort,remoteAddr&0xff,(remoteAddr >> 8)&0xff,(remoteAddr >> 16)&0xff,(remoteAddr >> 24)&0xff,remotePort,processName.c_str());
	double downSpeed = this->averageDownSpeed();
	double upSpeed = this->averageUpSpeed();
	if(bytesReceived >= 1024*1024) {
		fprintf(stderr,"    %.1f MB received ",bytesReceived/1024.0/1024.0);
	}
	else {
		fprintf(stderr,"    %.1f KB received ",bytesReceived/1024.0);
	}
	if(downSpeed >= 1024.0 * 1024.0) {
		fprintf(stderr,"(%.1f MB/s), ",downSpeed/1024.0/1024.0);
	}
	else {
		fprintf(stderr,"(%.1f KB/s), ",downSpeed/1024.0);
	}
	if(bytesSent >= 1024*1024) {
		fprintf(stderr,"%.1f MB sent ",bytesSent/1024.0/1024.0);
	}
	else {
		fprintf(stderr,"%.1f KB sent ",bytesSent/1024.0);
	}
	if(upSpeed >= 1024.0 * 1024.0) {
		fprintf(stderr,"(%.1f MB/s)\n",upSpeed/1024.0/1024.0);
	}
	else {
		fprintf(stderr,"(%.1f KB/s)\n",upSpeed/1024.0);
	}
}
