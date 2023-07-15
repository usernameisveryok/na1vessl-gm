#include "../src/netio.h"

int main()
{
    char buf[1024];
    auto c = receivebuf(sizeof(buf));

    // receivebuf((uint8_t *)buf, sizeof(buf));
    std::cout << "Message received: " << (char *)c.data() << std::endl;
    chunk a;
}