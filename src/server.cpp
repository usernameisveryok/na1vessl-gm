#include "message.h"
SM2_KEY key, clientkey;
uint8_t sessionkey[16];
SM4_KEY sm4key;
const uint8_t iv[16] = "karma";
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
    puts("client hello received!");
    print_bytes(ch.random, sizeof(ch.random));

    ServerCertificate sc;
    memcpy(sc.certificate, &key.public_key, sizeof(SM2_POINT));
    puts("server cert send!");
    sendmessage(sc);
    print_bytes(sc.certificate, sizeof(sc.certificate));

    ServerHello sh;
    puts("server hello sent!");
    sendmessage(sh);
    print_bytes(sh.random, sizeof(sh.random));

    ClientCertificate cc;
    puts("client cert sent");
    receivemessage(cc);
    memcpy(&clientkey.public_key, cc.certificate, sizeof(cc.certificate));

    CertificateVerify cv;
    puts("certtificate verify received!");
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
    puts("client exchange received!");
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
    puts("serverfinish sent");
    sendmessage(sf);

    ClientFinished cf;
    puts("received client finished!");
    receivemessage(cf);
    if (memcmp(cf.message_MAC, dgst, 32) != 0)
    {
        fprintf(stderr, "verify failed\n");
    }
    else
    {
        puts("channel established!");
    }

    uint8_t keylable[512] = "key", *keyin = keylable;
    keyin += 3;
    memcpy(keyin, ch.random, 32);
    keyin += 32;
    memcpy(keyin, sh.random, 32);
    keyin += 32;
    uint8_t raw[32];
    sm3_hmac(master_secret, 48, keylable, keyin - keylable, raw);
    // puts("sessionkey");
    // print_bytes(raw, 32);
    SM3_KDF_CTX ctx;
    sm3_kdf_init(&ctx, sizeof(sessionkey));
    sm3_kdf_update(&ctx, raw, sizeof(raw));
    sm3_kdf_finish(&ctx, (uint8_t *)&sessionkey);
    puts("session key");
    print_bytes((uint8_t *)&sessionkey, 16);
    return 0;
}
int work()
{
    puts("Let's chat!");
    AppliacationData ad;
    size_t len;
    uint8_t buf[1024];
    while (true)
    {

        receivemessage(ad);
        puts("get message");
        sm4_set_decrypt_key(&sm4key, sessionkey);
        sm4_cbc_decrypt(&sm4key, iv, ad.encryptedData, sizeof(ad.encryptedData) / SM4_BLOCK_SIZE, buf);
        puts((char *)buf);
        puts("---------------------------------------");
        puts("input:");
        scanf("%s", buf);
        sm4_set_encrypt_key(&sm4key, sessionkey);
        sm4_cbc_encrypt(&sm4key, iv, buf, sizeof(buf) / SM4_BLOCK_SIZE, ad.encryptedData);
        sendmessage(ad);
    }

    return 0;
};
int main()
{
    process();
    work();
}