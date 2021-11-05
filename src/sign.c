#include "secp256k1.h"
#include "hmac_sha3.h"
#include "uECC.h"

static void init_HMAC(const struct uECC_HashContext *base, const uint8_t *key, int key_len) {
    myc_hmac_sha3_256_init((myc_hmac_sha3_256_ctx *)base->ctx, key, key_len);
}

static void update_HMAC(const struct uECC_HashContext *base, const uint8_t *data, int len) {
    myc_hmac_sha3_256_update((myc_hmac_sha3_256_ctx *)base->ctx, data, len);
}

static void finish_HMAC(const struct uECC_HashContext *base, uint8_t *digest) {
    myc_hmac_sha3_256_final((myc_hmac_sha3_256_ctx *) base->ctx, digest, MYC_SHA3_256_DIGEST_LENGTH);
}

int myc_secp256k1_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *private_key) {

    uint8_t tmpsig[64];
    uint8_t tmp[2 * MYC_SHA3_256_DIGEST_LENGTH + 1];
    myc_hmac_sha3_256_ctx hmac_ctx;
    uECC_HashContext ctx = {
        &init_HMAC,
        &update_HMAC,
        &finish_HMAC,
        &hmac_ctx,
        MYC_SHA3_256_DIGEST_LENGTH,
        tmp
    };

    // Generate deterministic signature
    if (0 != uECC_sign_deterministic(private_key, message, message_len, &ctx, tmpsig)) {
        // Serialize to DER
        uECC_compact_to_der(tmpsig, signature);
        return 1;
    }

    return 0;
}
