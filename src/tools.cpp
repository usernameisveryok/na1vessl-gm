
#include "tools.h"
typedef uint8_t scalar[32];
extern const SM2_BN SM2_N;
extern const SM2_JACOBIAN_POINT *SM2_G;
struct ZKP
{
	scalar r1, r2, r3, c;
};
// 存储指针的，全局只存储一份 其他的都是直接存储值

struct ZKPP
{
	SM2_POINT *DID, PRFk, *H;
	scalar *sk, *hid, k;
};
struct ZKPPUB
{
	SM2_POINT *DID, PRFk, *H;
};

// how to compile
// g++(gcc) *.cpp PATH_TO_STATIC_LIB
int gen_did(SM2_POINT *did, const char *id, const char *Hseed, scalar sk)
{
	SM2_POINT H;
	scalar hid;
	scalar h;
	// did = g^hid*h^sk
	sm3_digest((uint8_t *)id, strlen(id), hid);
	sm2_point_mul_generator(did, hid);
	sm3_digest((uint8_t *)Hseed, strlen(Hseed), h);
	sm2_point_mul_generator(&H, h);
	sm2_point_mul(&H, sk, &H);
	sm2_point_add(did, &H, did);
	return 1;
}

int rand_nonzero_scalar(scalar s)
{
	SM2_BN x;
	do
	{
		sm2_bn_rand_range(x, SM2_N);
	} while (sm2_bn_is_zero(x));
	sm2_bn_to_bytes(x, s);
	return 1;
}
int did_to_pem(SM2_POINT *did, FILE *fp)
{
	uint8_t out[33];
	sm2_point_to_compressed_octets(did, out);
	if (pem_write(fp, "DID", out, sizeof(out)) <= 0)
	{
		error_print();
		return -1;
	}
	return 1;
}
int did_from_pem(SM2_POINT *did, FILE *fp)
{
	size_t out_len = 0;
	uint8_t in[33];
	if (pem_read(fp, "DID", in, &out_len, 4096) <= 0)
	{
		error_print();
		return -1;
	}
	sm2_point_from_octets(did, in, sizeof(in));
	return 1;
}
int getpswd(char *password)
{
	password = getpass("input password\n");
	if (strlen(password) <= 0)
	{
		return -1;
	}
	return 1;
}
int gen_H(const char *Hseed)
{
	FILE *fp = fopen("H.pem", "w");
	SM2_KEY _sm2_key, *sm2_key = &_sm2_key;
	sm2_point_from_hash(&sm2_key->public_key, (u_int8_t *)Hseed, strlen(Hseed));
	sm2_public_key_info_to_pem(sm2_key, fp);
	sm2_point_print(stdout, 0, 0, "H from pem", &sm2_key->public_key);
	fclose(fp);
	return 1;
}
int get_H(SM2_POINT *H)
{
	FILE *fp = fopen("H.pem", "r");
	SM2_KEY _sm2_key, *sm2_key = &_sm2_key;
	sm2_public_key_info_from_pem(sm2_key, fp);
	fclose(fp);
	// H = &sm2_key->public_key;
	memcpy(H, &sm2_key->public_key, sizeof(SM2_POINT));
	return 1;
}
int get_G(SM2_POINT *G)
{
	sm2_jacobian_point_to_bytes(SM2_G, (uint8_t *)G);
	return 1;
}

int gen_zkp(ZKP *zkp, const ZKPP *zkpp)
{

	SM2_POINT _G, *G = &_G, _p1, *p1 = &_p1, _p2,
				  *p2 = &_p2, _p3,
				  *p3 = &_p3, _t_1, *t_1 = &_t_1, _t_2, *t_2 = &_t_2;
	scalar v_1, v_2, v_3;
	SM3_CTX sm3_, *sm3 = &sm3_;
	int a = 1;
	rand_nonzero_scalar(v_1);
	rand_nonzero_scalar(v_2);
	rand_nonzero_scalar(v_3);

	get_G(G);
	a &= sm2_point_mul(p1, v_1, zkpp->H);
	a &= sm2_point_mul_generator(p2, v_2);
	a &= sm2_point_mul_generator(p3, v_3);
	a &= sm2_point_add(t_1, p1, p2);
	a &= sm2_point_add(t_2, p2, p3);
	if (a != 1)
		exit(-1);
	sm3_init(sm3);
	sm3_update(sm3, (u_int8_t *)G, sizeof(*G));
	sm3_update(sm3, (u_int8_t *)zkpp->H, sizeof(*zkpp->H));
	sm3_update(sm3, (u_int8_t *)zkpp->DID, sizeof(*zkpp->DID));
	sm3_update(sm3, (u_int8_t *)&zkpp->PRFk, sizeof(zkpp->PRFk));
	sm3_update(sm3, (u_int8_t *)t_1, sizeof(*t_1));
	sm3_update(sm3, (u_int8_t *)t_2, sizeof(*t_2));
	sm3_finish(sm3, zkp->c);
	SM2_Fn sk_bn, hid_bn, c_bn, v1_bn, v2_bn, v3_bn, k_bn;

	sm2_bn_from_bytes(sk_bn, *zkpp->sk);   // scalar
	sm2_bn_from_bytes(hid_bn, *zkpp->hid); // scalar
	sm2_bn_from_bytes(k_bn, zkpp->k);
	sm2_bn_from_bytes(c_bn, zkp->c);
	sm2_bn_from_bytes(v1_bn, v_1);
	sm2_bn_from_bytes(v2_bn, v_2);
	sm2_bn_from_bytes(v3_bn, v_3);

	sm2_fn_mul(sk_bn, sk_bn, c_bn);
	sm2_fn_mul(hid_bn, hid_bn, c_bn);
	sm2_fn_mul(k_bn, k_bn, c_bn);
	sm2_fn_mul(v1_bn, v1_bn, sk_bn);
	sm2_fn_mul(v2_bn, v2_bn, hid_bn);
	sm2_fn_mul(v3_bn, v3_bn, k_bn);

	sm2_bn_to_bytes(v1_bn, zkp->r1);
	sm2_bn_to_bytes(v2_bn, zkp->r2);
	sm2_bn_to_bytes(v3_bn, zkp->r3);

	return 1;
};
int zkp_ver(ZKP *zkp, ZKPPUB *zkppub)
{
	SM2_POINT _G, *G = &_G, _p1, *p1 = &_p1, _p2, did_, *did = &did_, prf_, *prf = &prf_,
				  *p2 = &_p2, _p3,
				  *p3 = &_p3, _t_1, *t_1 = &_t_1, _t_2, *t_2 = &_t_2;
	scalar c;
	get_G(G);
	sm2_point_mul(did, zkp->c, zkppub->DID);
	sm2_point_mul(prf, zkp->c, &zkppub->PRFk);
	sm2_point_mul(p1, zkp->r1, zkppub->H);
	sm2_point_mul(p1, zkp->r1, zkppub->H);
	sm2_point_mul_generator(p2, zkp->r2);
	sm2_point_mul_generator(p3, zkp->r3);
	sm2_point_add(t_1, p1, p2);
	sm2_point_add(t_1, t_1, did);

	sm2_point_add(t_2, p2, p3);
	sm2_point_add(t_2, t_2, prf);
	// sm2_point_print(stdout, 0, 0, "vert1", t_1);
	// sm2_point_print(stdout, 0, 0, "vert2", t_2);
	SM3_CTX sm3_, *sm3 = &sm3_;
	sm3_init(sm3);

	sm3_update(sm3, (u_int8_t *)G, sizeof(SM2_POINT));
	sm3_update(sm3, (u_int8_t *)zkppub->H, sizeof(SM2_POINT));
	sm3_update(sm3, (u_int8_t *)zkppub->DID, sizeof(SM2_POINT));
	sm3_update(sm3, (u_int8_t *)&zkppub->PRFk, sizeof(SM2_POINT));
	sm3_update(sm3, (u_int8_t *)t_1, sizeof(SM2_POINT));
	sm3_update(sm3, (u_int8_t *)t_2, sizeof(SM2_POINT));
	sm3_finish(sm3, c);
	return memcmp(zkp->c, c, sizeof(scalar));
}
// int get_AB(SM2_POINT *A, SM2_POINT *B, SM2_POINT *prf_k1, SM2_POINT *gk1, SM2_POINT *did)
// {
// 	sm2_point_sub(A, prf_k1, gk1);
// 	sm2_point_sub(B, did, A);
// 	return 0;
// }
int test_shnorr()
{
	scalar v, hid, c, r;
	rand_nonzero_scalar(v);
	rand_nonzero_scalar(hid);
	rand_nonzero_scalar(c);
	SM2_POINT p, pp, G, did;
	SM2_Fn a, b, cc;
	sm2_point_mul_generator(&p, v);
	sm2_point_mul_generator(&did, hid);
	sm2_bn_from_bytes(a, v);
	sm2_bn_from_bytes(b, hid);
	sm2_bn_from_bytes(cc, c);
	sm2_fn_mul(b, b, cc);
	sm2_fn_sub(a, a, b);
	sm2_bn_to_bytes(a, r);
	sm2_point_mul_generator(&pp, r);
	sm2_point_mul(&did, c, &did);
	sm2_point_add(&pp, &did, &pp);
	return memcmp(&pp, &p, sizeof(pp));
}
int test_fn()
{
	scalar v, vv;
	rand_nonzero_scalar(v);
	rand_nonzero_scalar(vv);
	SM2_BN a, b;

	sm2_bn_from_bytes(a, v);
	sm2_bn_from_bytes(b, vv);
	SM2_POINT p, pp;
	sm2_point_mul_generator(&p, v);
	// sm2_point_mul_generator(&p, vv);
	sm2_point_mul(&p, vv, &p);
	// sm2_point_add(&p, &pp, &p);
	sm2_fn_mul(a, a, b); // 加法使用fn
	sm2_bn_to_bytes(a, v);
	sm2_point_mul_generator(&pp, v);
	uint8_t out[33];
	uint8_t out1[33];
	sm2_point_to_compressed_octets(&p, out);
	sm2_point_to_compressed_octets(&p, out);
	sm2_point_print(stdout, 0, 0, "a", &p);
	sm2_point_print(stdout, 0, 0, "b", &pp);
	return memcmp(&p, &pp, sizeof(p));
}

int demo()
{
	SM2_KEY _sm2_key, *sm2_key = &_sm2_key;
	SM2_POINT _did, *did = &_did, _H, *H = &_H;
	FILE *fp;
	ZKP zkp;
	scalar hid;

	char id[128] = "3891273987189273";
	const char *Hseed = "123456";
	gen_H(Hseed);
	get_H(H);
	sm3_digest((uint8_t *)id, strlen(id), hid);
	sm2_point_print(stdout, 0, 0, "H from pem", H);
	// insname = insname + ".pem";

	if (sm2_key_generate(sm2_key) != 1)
	{
		fprintf(stderr, "error\n");
		return 1;
	}
	fp = fopen("sk.pem", "w");

	char password[128] = "123";
	// password = getpass("input pswd");
	if (sm2_private_key_info_encrypt_to_pem(sm2_key, password, fp) != 1)
	{
		fprintf(stderr, "error\n");
		return 1;
	}
	fclose(fp);

	fp = fopen("sk.pem", "r");
	if (sm2_private_key_info_decrypt_from_pem(sm2_key, password, fp) != 1)
	{
		fprintf(stderr, "error\n");
		return 1;
	}
	fclose(fp);
	gen_did(did, id, Hseed, sm2_key->private_key);
	sm2_point_print(stdout, 0, 0, "did", did);
	fp = fopen("did.pem", "w");
	if (did_to_pem(did, fp) != 1)
	{
		fprintf(stderr, "error\n");
		return 1;
	}
	fclose(fp);
	fp = fopen("did.pem", "r");
	if (did_from_pem(did, fp) != 1)
	{
		fprintf(stderr, "error\n");
		return 1;
	}
	sm2_point_print(stdout, 0, 0, "did", did);
	fclose(fp);
	// struct ZKPP
	// {
	// 	SM2_POINT *DID, PRFk, *H;
	// 	scalar *sk, *hid, k;
	// };
	SM2_POINT prf;
	scalar k1;
	rand_nonzero_scalar(k1);
	sm2_point_mul_generator(&prf, k1);

	sm2_point_mul(&prf, k1, &prf);

	ZKPP zkpp;
	zkpp.DID = did;
	zkpp.H = H;
	zkpp.hid = &hid;
	zkpp.PRFk = prf;
	memcpy(zkpp.k, k1, sizeof(k1));
	zkpp.sk = &sm2_key->private_key;
	ZKPPUB zkpub;
	zkpub.DID = did;
	zkpub.H = H;
	zkpub.PRFk = prf;
	time_t now = time(0);
	for (size_t i = 0; i < 2000; i++)
	{
		// gen_zkp(&zkp, &zkpp);
		zkp_ver(&zkp, &zkpub);
	}
	time_t end = time(0);
	printf("%ld\n", end - now);

	zkp_ver(&zkp, &zkpub);
	// int a = test_fn();
	// printf("%d\n", a);

	return 0;
	/*
		please use compressed octets when send points
		pem only for files
		sm2_point_to_compressed_octets(did, out);
		sm2_point_from_octets(did, in, sizeof(in))
	*/
	//
}
int main()
{
	demo();
}
