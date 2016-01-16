#ifndef _INCLUDE_UTIL_H_
#define _INCLUDE_UTIL_H_

#include <stdbool.h>

const char *fm_typestr(int type);
const char *fm_colorstr(int type);
void hexdump(const uint8_t *buf, unsigned int len, int w);
const char * getProcName(int pid, int *ppid);
bool is_directory (const char *str);
bool copy_file(const char *src, const char *dst);

/* plain colors */
#define Color_RESET      "\x1b[0m"
#define Color_BLACK      "\x1b[30m"
#define Color_BGBLACK    "\x1b[40m"
#define Color_RED        "\x1b[31m"
#define Color_BGRED      "\x1b[41m"
#define Color_WHITE      "\x1b[37m"
#define Color_BGWHITE    "\x1b[47m"
#define Color_GREEN      "\x1b[32m"
#define Color_BGGREEN    "\x1b[42m"
#define Color_MAGENTA    "\x1b[35m"
#define Color_BGMAGENTA  "\x1b[45m"
#define Color_YELLOW     "\x1b[33m"
#define Color_BGYELLOW   "\x1b[43m"
#define Color_CYAN       "\x1b[36m"
#define Color_BGCYAN     "\x1b[46m"
#define Color_BLUE       "\x1b[34m"
#define Color_BGBLUE     "\x1b[44m"
#define Color_GRAY       "\x1b[38m"
#define Color_BGGRAY     "\x1b[48m"
/* bold colors */
#define Color_BBLACK    "\x1b[1;30m"
#define Color_BRED      "\x1b[1;31m"
#define Color_BBGRED    "\x1b[1;41m"
#define Color_BWHITE    "\x1b[1;37m"
#define Color_BGREEN    "\x1b[1;32m"
#define Color_BMAGENTA  "\x1b[1;35m"
#define Color_BYELLOW   "\x1b[1;33m"
#define Color_BCYAN     "\x1b[1;36m"
#define Color_BBLUE     "\x1b[1;34m"
#define Color_BGRAY     "\x1b[1;38m"
#endif
