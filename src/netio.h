#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#define PORT 8080
#define IP "127.0.0.1"
typedef std::vector<u_int8_t> chunk;
int receivebuf(uint8_t *buffer, size_t len);
int sendbuf(uint8_t *buffer, size_t len);
chunk receivebuf(size_t len);
int sendbuf(chunk data);