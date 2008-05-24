#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <glib.h>

#include "config.h"

extern struct config cfg;

void logger_init(void)
{
	if (cfg.daemon)
		openlog("susanin", 0, LOG_DAEMON);
}

void log_msg(int pri, const char *fmt, ...)
{
	char *format;
	int maxlen;
	va_list args;

	maxlen = strlen(fmt) + 100;
	if (!(format = malloc(maxlen)))
		return;
	va_start(args, fmt);
	vsnprintf(format, maxlen, fmt, args);
	va_end(args);
	if (cfg.daemon)
		syslog(pri, "%s", format);
	else
		printf("%s\n", format);
	free(format);
}
