#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include "log.h"

void log_printf(const char *format ...)
{
	va_list argp;
	va_start(argp, format);
	vfprintf(stderr, format, argp);
	va_end(argp);
	
	FILE *fp = fopen("log.txt","a");
	if(!fp) return;
	va_start(argp, format);
	vfprintf(fp, format, argp);
	va_end(argp);
	fclose(fp);
}

void log_dated_printf(const char *format ...)
{
	char timeStr[32];
	time_t t;
	time(&t);
	struct tm *tm =localtime(&t);
	strftime(timeStr, 32, "%Y/%m/%d %H:%M:%S", tm);
	
	fprintf(stderr,"[%s]",timeStr);
	va_list argp;
	va_start(argp, format);
	vfprintf(stderr, format, argp);
	va_end(argp);
	
	FILE *fp = fopen("log.txt","a");
	if(!fp) return;
	fprintf(fp,"[%s]",timeStr);
	va_start(argp, format);
	vfprintf(fp, format, argp);
	va_end(argp);
	fclose(fp);
}