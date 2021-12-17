#include <secp256k1.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void print(const uint8_t *data, int length) {
    for (int i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
}

int main() {
    uint8_t seed[32] = {0};
    uint8_t private_key[32] = {0};
    uint8_t public_key[33] = {0};

    // Generate random seed
    arc4random_buf(seed, sizeof seed);

    // Create key pair
    myc_secp256k1_create_keypair(public_key, private_key, seed);

    printf("Private key: ");
    print(private_key, sizeof(private_key));
    printf("\n");

    printf("Public key: ");
    print(public_key, sizeof(public_key));
    printf("\n");
}
