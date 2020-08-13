#include "secp256k1.h"
#include "uECC.h"

int secp256k1_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar) {
    const struct uECC_Curve_t* secp256k1 = uECC_secp256k1();

    // Space for key decompression
    unsigned char decompressed[64];

    int failed = 0;

    if (public_key) {
        // Keys must be uncompressed first
        uECC_decompress(public_key, decompressed, secp256k1);

        // Tweak public key
        failed |= !uECC_public_point_tweak(decompressed, decompressed, scalar, secp256k1);

        // Compress it back
        uECC_compress(decompressed, public_key, secp256k1);
    }

    if (private_key) {
        failed |= !uECC_private_scalar_tweak(private_key, private_key, scalar, secp256k1);
    }

    return !failed;
}
