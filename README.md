# secp256k1 utilities library

This library is focused on providing secp256k1 signing and verification.

### API

```c
/*
 * Derive private key from 256 bits of private seed.
 */
void secp256k1_create_privkey(unsigned char *private_key, const unsigned char *seed);
```

```c
/*
 * Derive private and public key from 256 bits of private seed.
 */
 void secp256k1_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
 ```
 
 ```c
 /*
  * Get secp256k1 public key from private key.
  */
  void secp256k1_get_pubkey(unsigned char *public_key, const unsigned char *private_key);
  
  ```c
  /*
   * Sign message using key pair.
   */
  void secp256k1_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
  ```
  
  ```c
  /*
   * Verify secp256k1 signature
   */
  int secp256k1_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);
  ```
  
  ```c
  /*
   * Tweak public or private key using the given scalar.
   */
  int secp256k1_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar);
  ```
  
