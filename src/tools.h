#include <gmssl/sm3.h>
#include <gmssl/sm2.h>
#include <gmssl/ec.h>
#include <gmssl/base64.h>
#include <gmssl/error.h>
#include <gmssl/pem.h>
#include <unistd.h>
int gen_did(SM2_POINT *did, const char *id, const char *Hseed, uint8_t sk[32]);
int did_to_pem(SM2_POINT *did, FILE *fp);
int did_from_pem(SM2_POINT *did, FILE *fp);
int getpswd(char *password);
int gen_H(const char* Hseed);
int get_H(SM2_POINT *H);
