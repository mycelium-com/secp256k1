#include "secp256k1.h"
#include "sha3.h"
#include "uECC.h"
#include "types.h"

void secp256k1_get_pubkey(unsigned char *public_key, const unsigned char *private_key) {
    unsigned char tmp[64];
    uECC_compute_public_key(private_key, tmp);
    uECC_compress(tmp, public_key);
}

void secp256k1_create_privkey(unsigned char *private_key, const unsigned char *seed) {
    sha3_256(seed, 32, private_key);
}

void secp256k1_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {
    sha3_256(seed, 32, private_key);
    secp256k1_get_pubkey(public_key, private_key);
}
