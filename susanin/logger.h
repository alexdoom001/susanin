#ifndef LOGGER_H
#define LOGGER_H

void logger_init(void);
void log_msg(int pri, const char *fmt, ...);

#endif /* LOGGER_H */
