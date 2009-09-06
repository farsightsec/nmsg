#define DEBUG 1
#define VERBOSE(format, ...) do { printf("%s(%d): " format, __func__, __LINE__, ## __VA_ARGS__); } while(0)
