#include "secp256k1.h"
#include "sha3.h"
#include "uECC.h"
#include "types.h"

#include <string.h>

int myc_secp256k1_verify_privkey(const unsigned char *private_key) {
    return uECC_valid_private_key(private_key);
}

int myc_secp256k1_verify_pubkey(const unsigned char *public_key) {
    unsigned char tmp[64];
    const unsigned char *ptmp = public_key + 1;

    // Check prefix
    if (public_key[0] != 0x04 && public_key[0] != 0x02 && public_key[0] != 0x03)
        return 0;

    myc_secp256k1_decompress_pubkey(tmp, public_key);
    return uECC_valid_public_key(tmp);
}

void myc_secp256k1_compress_pubkey(unsigned char *compressed, const unsigned char *public_key) {
    if (public_key[0] == 0x04) {
        uECC_compress(public_key + 1, compressed);
    } else {
        memcpy(compressed, public_key, 33);
    }
}

void myc_secp256k1_decompress_pubkey(unsigned char *decompressed, const unsigned char *public_key) {
    if (public_key[0] != 0x04) {
        decompressed[0] = 0x04;
        uECC_decompress(public_key, decompressed + 1);
    } else {
        memcpy(decompressed, public_key, 65);
    }
}

void myc_secp256k1_get_compressed_pubkey(unsigned char *public_key, const unsigned char *private_key) {
    unsigned char tmp[64];
    uECC_compute_public_key(private_key, tmp);
    uECC_compress(tmp, public_key);
}

void myc_secp256k1_get_uncompressed_pubkey(unsigned char *public_key, const unsigned char *private_key) {
    public_key[0] = 0x04;
    uECC_compute_public_key(private_key, public_key);
}

void myc_secp256k1_get_pubkey(unsigned char *public_key, const unsigned char *private_key) {
    return myc_secp256k1_get_compressed_pubkey(public_key, private_key);
}

void myc_secp256k1_create_privkey(unsigned char *private_key, const unsigned char *seed) {
    myc_sha3_256(seed, 32, private_key);
}

void myc_secp256k1_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {
    myc_sha3_256(seed, 32, private_key);
    myc_secp256k1_get_pubkey(public_key, private_key);
}
