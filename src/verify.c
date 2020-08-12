#include "secp256k1.h"
#include "uECC.h"

int secp256k1_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key) {
    
    const struct uECC_Curve_t* secp256k1 = uECC_secp256k1();

    // Space for key decompression
    unsigned char tmp[64];
    const unsigned char *uecc_pubkey;

    // Space for deserialized signature
    uint8_t tmpsig[64];

    // Compressed keys must be uncompressed first
    if (public_key[0] != 0x04) {
        // Decompress public key
        uECC_decompress(public_key, tmp, secp256k1);
        uecc_pubkey = tmp;
    }

    if (public_key[0] == 0x04) {
        // Set public key pointer
        uecc_pubkey = public_key + 1;
    }

    // Deserialize
    uECC_deserialize_der(signature, tmpsig, secp256k1);

    // Verify deserialized signature
    return uECC_verify(uecc_pubkey, message, message_len, tmpsig, secp256k1);
}
