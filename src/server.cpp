#include <gmssl/sm3.h>
#include <gmssl/sm2.h>
#include <gmssl/ec.h>
#include <gmssl/base64.h>
#include <gmssl/error.h>
#include <gmssl/pem.h>
#include <gmssl/rand.h>
#include <unistd.h>
#include "utils.h"

int process()
{
    ClientHello ch;
    receivemessage(ch);
    print_bytes(ch.random, sizeof(ch.random));
    return 0;
}
int work() { return 0; };
int main()
{
    process();
    work();
}