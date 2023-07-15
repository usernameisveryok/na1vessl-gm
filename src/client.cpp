#include <gmssl/sm3.h>
#include <gmssl/sm2.h>
#include <gmssl/ec.h>
#include <gmssl/base64.h>
#include <gmssl/error.h>
#include <gmssl/pem.h>
#include <gmssl/rand.h>
#include <unistd.h>
#include "utils.h"
SM2_KEY key, serverkey;
int process()
{
    const char *pass = "karma";
    FILE *fp = fopen("../certificate/client.pub", "r");
    sm2_public_key_info_from_pem(&key, fp);
    fclose(fp);
    fp = fopen("../certificate/client", "r");
    sm2_private_key_info_decrypt_from_pem(&key, pass, fp);
    fclose(fp);

    ClientHello ch;
    rand_bytes(ch.random, 32); // get rand
    sendmessage(ch);
    print_bytes(ch.random, sizeof(ch.random));

    ServerCertificate sc;
    receivemessage(sc);
    print_bytes(sc.certificate, sizeof(sc.certificate));
    memcpy(&serverkey.public_key, sc.certificate, sizeof(sc.certificate));

    ServerHello sh;
    receivemessage(sh);
    print_bytes(sh.random, sizeof(sh.random));

    ClientCertificate cc;
    uint8_t master_secret[48];
    rand_bytes(master_secret, 48);
    sm2_encrypt(&serverkey, master_secret, 48, cc.certificate, &cc.len);
    sendmessage(cc);
    print_bytes(cc.certificate, cc.len);
    print_bytes(master_secret, 48);

    
    return 0;
}
int work() { return 0; };
int main()
{
    process();
    work();
}