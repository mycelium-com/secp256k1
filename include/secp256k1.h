#ifndef SECP256K1_H
#define SECP256K1_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void secp256k1_get_pubkey(unsigned char *public_key, const unsigned char *private_key);
void secp256k1_create_privkey(unsigned char *private_key, const unsigned char *seed);
void secp256k1_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
void secp256k1_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
int secp256k1_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);
int secp256k1_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar);

#ifdef __cplusplus
}
#endif

#endif
