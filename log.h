#ifndef __ERR_H__
#define __ERR_H__

extern int log_init(const char *fname);
extern void log_close(void);
extern void log_err(char *fname, const char *func, int lineno, char *fmt, ...);
extern void log_debug(FILE *fp, char *fname, const char *func, int lineno, char *fmt, ...);
extern int get_dev_mountpoint(const char *dev, char *mntpoint);
void log_reset_size(const char *fname);

#define DPRINTF(fmt, arg...) do {log_err(__FILE__, __FUNCTION__ ,  __LINE__, fmt, ##arg); } while (0)
#define DEBUG(fmt, arg...) do {log_debug(stderr, __FILE__, __FUNCTION__ ,  __LINE__, fmt, ##arg); } while (0)

#endif /* __ERR_H__ */
