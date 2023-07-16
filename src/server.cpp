#include <gmssl/sm3.h>
#include <gmssl/sm2.h>
#include <gmssl/ec.h>
#include <gmssl/base64.h>
#include <gmssl/error.h>
#include <gmssl/pem.h>
#include <gmssl/rand.h>
#include <unistd.h>
#include "utils.h"
SM2_KEY key, clientkey;

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
    receivemessage(cc);
    memcpy(&clientkey.public_key, cc.certificate, sizeof(cc.certificate));

    CertificateVerify cv;
    receivemessage(cv);
    uint8_t dgst[32], concat[128];
    memcpy(concat, sh.random, 32);
    memcpy(concat + 32, ch.random, 32);
    memcpy(concat + 64, sc.certificate, 64);
    sm3_digest(concat, 128, dgst);
    int ret;
    if ((ret = sm2_verify(&clientkey, dgst, cv.signature, cv.len)) != 1)
    {
        fprintf(stderr, "verify failed\n");
        return 0;
    }
    ClientKeyExchange ce;
    receivemessage(ce);
    uint8_t master_secret[48];
    print_bytes(ce.encryptedSharedSecret, ce.len);
    size_t out;
    sm2_decrypt(&key, ce.encryptedSharedSecret, ce.len, master_secret, &out);
    puts("shared secret");
    print_bytes(master_secret, 48);

    ServerFinished sf;
    uint8_t handshakemsg[512], *inmsg = handshakemsg;
    memcpy(inmsg, ch.random, 32);
    inmsg += 32;
    memcpy(inmsg, sh.random, 32);
    inmsg += 32;
    sm3_digest(sc.certificate, 64, inmsg);
    inmsg += 32;
    sm3_digest(cc.certificate, 64, inmsg);
    inmsg += 32;
    memcpy(inmsg, cv.signature, cv.len);
    inmsg += cv.len;
    memcpy(inmsg, ce.encryptedSharedSecret, ce.len);
    inmsg += ce.len;
    sm3_digest(handshakemsg, inmsg - handshakemsg, dgst);
    print_bytes(dgst, 32);
    uint8_t clientfinish[512] = "client";
    uint8_t serverfinish[512] = "server";
    memcpy(clientfinish + 6, handshakemsg, 32);
    memcpy(serverfinish + 6, dgst, 32);
    sm3_hmac(master_secret, 48, clientfinish, 32 + 6, dgst);
    sm3_hmac(master_secret, 48, serverfinish, 32 + 6, sf.message_MAC);
    sendmessage(sf);

    ClientFinished cf;
    receivemessage(cf);
    if (memcmp(cf.message_MAC, dgst, 32) != 0)
    {
        fprintf(stderr, "verify failed\n");
    }
    else
    {
        puts("channel established!");
    }

    return 0;
}
int work() { return 0; };
int main()
{
    process();
    work();
}