#include <gmssl/sm3.h>
#include <gmssl/sm2.h>
#include <gmssl/ec.h>
#include <gmssl/base64.h>
#include <gmssl/error.h>
#include <gmssl/pem.h>
#include <gmssl/rand.h>
#include <unistd.h>
#include "utils.h"

SM2_KEY key;
int process()
{

    ClientHello ch;
    receivemessage(ch);
    print_bytes(ch.random, sizeof(ch.random));

    FILE *fp = fopen("../certificate/server.pub", "r");
    sm2_public_key_info_from_pem(&key, fp);
    fclose(fp);

    ServerCertificate sc;
    memcpy(sc.certificate, &key.public_key, sizeof(SM2_POINT));
    sendmessage(sc);
    print_bytes(sc.certificate, sizeof(sc.certificate));

    ServerHello sh;
    sendmessage(sh);
    print_bytes(sh.random, sizeof(sh.random));

    return 0;
}
int work() { return 0; };
int main()
{
    process();
    work();
}