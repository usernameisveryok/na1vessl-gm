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
    const char *pass = "karma";
    FILE *fp = fopen("../certificate/server.pub", "r");
    sm2_public_key_info_from_pem(&key, fp);
    fclose(fp);
    fp = fopen("../certificate/server", "r");
    sm2_private_key_info_decrypt_from_pem(&key, pass, fp);
    fclose(fp);

    ClientHello ch;
    receivemessage(ch);
    print_bytes(ch.random, sizeof(ch.random));

    ServerCertificate sc;
    memcpy(sc.certificate, &key.public_key, sizeof(SM2_POINT));
    sendmessage(sc);
    print_bytes(sc.certificate, sizeof(sc.certificate));

    ServerHello sh;
    sendmessage(sh);
    print_bytes(sh.random, sizeof(sh.random));

    ClientCertificate cc;
    uint8_t master_secret[48];
    receivemessage(cc);
    print_bytes(cc.certificate, cc.len);
    size_t out;
    sm2_decrypt(&key, cc.certificate, cc.len, master_secret, &out);
    print_bytes(master_secret, 48);
    
    return 0;
}
int work() { return 0; };
int main()
{
    process();
    work();
}