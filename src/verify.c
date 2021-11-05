#include "secp256k1.h"
#include "uECC.h"

int myc_secp256k1_verify(const unsigned char *signature, const unsigned int signature_len, const unsigned char *message, size_t message_len, const unsigned char *public_key) {

    // Space for key decompression
    unsigned char decompressed[64];
    const unsigned char *pdecompressed = public_key + 1;

    // Space for deserialized signature
    uint8_t tmpsig[64];

    if (public_key[0] != 0x04) {
        // Decompress public key
        uECC_decompress(public_key, decompressed);
        pdecompressed = &decompressed[0];
    }

    // Deserialize
    uECC_der_to_compact(signature, signature_len, tmpsig);

    // Verify deserialized signature
    return uECC_verify(pdecompressed, message, message_len, tmpsig);
}
