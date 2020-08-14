#include "secp256k1.h"
#include "uECC.h"

int secp256k1_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar) {
    // Space for key decompression
    unsigned char decompressed[64];

    int failed = 0;

    if (public_key) {
        // Keys must be uncompressed first
        uECC_decompress(public_key, decompressed);

        // Tweak public key
        failed |= !uECC_public_point_tweak(decompressed, decompressed, scalar);

        // Compress it back
        uECC_compress(decompressed, public_key);
    }

    if (private_key) {
        failed |= !uECC_private_scalar_tweak(private_key, private_key, scalar);
    }

    return !failed;
}
