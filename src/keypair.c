#include "secp256k1.h"
#include "sha2.h"

#include <openssl/evp.h>
#include <openssl/ecdsa.h>

void secp256k1_get_pubkey(unsigned char *public_key, const unsigned char *private_key) {
    // stub
}

void secp256k1_create_privkey(unsigned char *private_key, const unsigned char *seed) {
    // stub
}

void secp256k1_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {
    // stub
}
