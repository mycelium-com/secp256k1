#include "secp256k1.h"
#include "sha3.h"
#include "uECC.h"

typedef struct HashContext {
    uECC_HashContext uECC;
    SHA3_CTX ctx;
} HashContext;

static void init_hash(const uECC_HashContext *base) {
    HashContext *context = (HashContext *)base;
    sha3_256_Init(&context->ctx);
}

static void update_hash(const uECC_HashContext *base, const uint8_t *message, unsigned message_size) {
    HashContext *context = (HashContext *)base;
    sha3_Update(&context->ctx, message, message_size);
}

static void finish_hash(const uECC_HashContext *base, uint8_t *hash_result) {
    HashContext *context = (HashContext *)base;
    sha3_Final(&context->ctx, hash_result);
}

void secp256k1_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key) {

    const struct uECC_Curve_t* secp256k1 = uECC_secp256k1();

    uint8_t tmpsig[64];
    uint8_t tmp[2 * SHA3_256_DIGEST_LENGTH + SHA3_256_BLOCK_LENGTH];
    HashContext ctx = {{
        &init_hash,
        &update_hash,
        &finish_hash,
        SHA3_256_BLOCK_LENGTH,
        SHA3_256_DIGEST_LENGTH,
        tmp
    }};

    // Generate deterministic signature
    uECC_sign_deterministic(private_key, message, message_len, &ctx.uECC, tmpsig, secp256k1);
    
    // Only low-S signatures are considered valid
    uECC_normalize_signature(tmpsig, secp256k1);

    // Serialize to DER
    uECC_serialize_der(tmpsig, signature);
}
