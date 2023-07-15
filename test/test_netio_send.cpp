#include "../src/netio.h"
int main()
{
    char buf[1024] = "helloworld";
    std::vector<uint8_t> vec(buf,buf + sizeof(buf) / sizeof(buf[0]));
    sendbuf(vec);
}