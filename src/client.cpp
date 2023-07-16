#include "utils.h"
SM2_KEY key, serverkey;
uint8_t sessionkey[16];
SM4_KEY sm4key;
const uint8_t iv[16] = "karma";
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
    memcpy(cc.certificate, &key.public_key, sizeof(cc.certificate));
    sendmessage(cc);

    CertificateVerify cv;
    uint8_t dgst[32], concat[128];
    memcpy(concat, sh.random, 32);
    memcpy(concat + 32, ch.random, 32);
    memcpy(concat + 64, sc.certificate, 64);
    sm3_digest(concat, 128, dgst);
    sm2_sign(&key, dgst, cv.signature, &cv.len);
    sendmessage(cv);

    ClientKeyExchange ce;
    uint8_t master_secret[48];
    rand_bytes(master_secret, 48);
    sm2_encrypt(&serverkey, master_secret, 48, ce.encryptedSharedSecret, &ce.len);
    sendmessage(ce);
    print_bytes(ce.encryptedSharedSecret, ce.len);
    puts("shared secret");
    print_bytes(master_secret, 48);

    ServerFinished sf;
    receivemessage(sf);

    ClientFinished cf;
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
    sm3_hmac(master_secret, 48, clientfinish, 32 + 6, cf.message_MAC);
    sm3_hmac(master_secret, 48, serverfinish, 32 + 6, dgst);
    sendmessage(cf);

    if (memcmp(sf.message_MAC, dgst, 32) != 0)
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
        puts("input:");
        scanf("%s",buf);
        sm4_set_encrypt_key(&sm4key, sessionkey);
        sm4_cbc_encrypt(&sm4key, iv, buf, sizeof(buf) / SM4_BLOCK_SIZE, ad.encryptedData);
        sendmessage(ad);
        puts("get message");
        receivemessage(ad);
        sm4_set_decrypt_key(&sm4key, sessionkey);
        sm4_cbc_decrypt(&sm4key, iv, ad.encryptedData, sizeof(ad.encryptedData) / SM4_BLOCK_SIZE, buf);
        puts((char *)buf);
    }
    
    return 0;
};
int main()
{
    process();
    work();
}