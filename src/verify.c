#include "secp256k1.h"
#include "uECC.h"

int secp256k1_verify(const unsigned char *signature, const unsigned int signature_len, const unsigned char *message, size_t message_len, const unsigned char *public_key) {

    // Space for key decompression
    unsigned char tmp[64];

    // Space for deserialized signature
    uint8_t tmpsig[64];

    // Decompress public key
    uECC_decompress(public_key, tmp);

    // Deserialize
    uECC_der_to_compact(signature, signature_len, tmpsig);

    // Verify deserialized signature
    return uECC_verify(tmp, message, message_len, tmpsig);
}
