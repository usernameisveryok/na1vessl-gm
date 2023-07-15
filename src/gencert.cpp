#include <gmssl/sm3.h>
#include <gmssl/sm2.h>
#include <gmssl/ec.h>
#include <gmssl/base64.h>
#include <gmssl/error.h>
#include <gmssl/pem.h>
#include <gmssl/rand.h>
#include <unistd.h>

int main()
{
    const char *pass = "karma";
    SM2_KEY sm2_key_, *sm2_key;
    if (sm2_key_generate(sm2_key) != 1)
    {
        fprintf(stderr, "gen cert error\n");
        return 1;
    }
    FILE *fp = fopen("../certificate/server.pub", "w");
    sm2_public_key_info_to_pem(sm2_key, fp);
    fclose(fp);
    fp = fopen("../certificate/server", "w");
    sm2_private_key_info_encrypt_to_pem(sm2_key, pass, fp);
    fclose(fp);
    if (sm2_key_generate(sm2_key) != 1)
    {
        fprintf(stderr, "gen cert error\n");
        return 1;
    }
    fp = fopen("../certificate/client.pub", "w");
    sm2_public_key_info_to_pem(sm2_key, fp);
    fclose(fp);
    fp = fopen("../certificate/client", "w");
    sm2_private_key_info_encrypt_to_pem(sm2_key, pass, fp);
    fclose(fp);
}