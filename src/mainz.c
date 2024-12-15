#include "utils.c"
#include "psa/crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/psa_util.h"

#define CURVE_BITS 521
// 521 bits is 66 bytes rounded up and we need 2 values in the signature
#define SIGNATURE_BYTES 132

unsigned char signature_contents[] = {
  0x30, 0x81, 0x88, 0x02, 0x42, 0x01, 0xda, 0xe6, 0x4b, 0x97, 0x54, 0x95,
  0xc4, 0xcc, 0x67, 0x1d, 0xc5, 0xa6, 0x58, 0x97, 0xa8, 0xff, 0x44, 0x3a,
  0x6c, 0x73, 0xac, 0xec, 0x32, 0x51, 0x35, 0xc1, 0x64, 0x88, 0xcf, 0x32,
  0x74, 0xcf, 0x98, 0xf5, 0x7f, 0xde, 0xdf, 0xc4, 0x95, 0xd9, 0x5f, 0xae,
  0x93, 0x41, 0x73, 0xfd, 0x2e, 0x2b, 0x10, 0xf2, 0x58, 0x29, 0xf9, 0xe6,
  0x74, 0x07, 0xc7, 0xf3, 0x4b, 0xc1, 0xcf, 0x83, 0xd5, 0x44, 0xb2, 0x02,
  0x42, 0x00, 0xec, 0x9d, 0xf9, 0x68, 0x5d, 0xf1, 0x8e, 0x87, 0xb1, 0xbe,
  0x77, 0xc2, 0xf8, 0x0e, 0xd5, 0x15, 0xc1, 0x4c, 0x40, 0xf6, 0x32, 0xa3,
  0xe2, 0x21, 0xe4, 0xde, 0x11, 0xd1, 0x12, 0x19, 0xb2, 0x63, 0xea, 0xbb,
  0x69, 0x67, 0xc7, 0x7a, 0x81, 0xfd, 0xe6, 0xb8, 0xa8, 0xa8, 0x24, 0xf0,
  0xf3, 0x42, 0x59, 0x64, 0x2a, 0xb7, 0xda, 0xc8, 0x8c, 0x98, 0x84, 0x72,
  0x39, 0xb6, 0x4e, 0x7d, 0x41, 0xd3, 0x17
};
unsigned int signature_contents_length = 139;

const unsigned char public_pem[] = "-----BEGIN PUBLIC KEY-----\n\
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBGczRY7yIrPoYbvbX30Wcu/btw0ba\n\
9IQlqiCB2O2kx+8ZJ+E6Y0eu/P6o4Ybmqm8TjExIJUhLsbxdJ5q24zURcwoBot/P\n\
SCSGwFh5R71enhZ5/KmLyFgOZ3OxuBDWO0Li+R9u83j8M9Q+52PX6qInF6UVLJiV\n\
yZGKdW/9KczQCq//Jys=\n\
-----END PUBLIC KEY-----\n";
const unsigned int public_pem_len = sizeof(public_pem);
unsigned char signme_contents[] = {
  0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x20,
  0x73, 0x69, 0x67, 0x6e, 0x20, 0x6d, 0x65, 0x0a
};
unsigned int signme_contents_length = 20;

int main() {
    psa_status_t status;
    int ret = 0;

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		printf("psa_crypto_init failed! (Error: %d)\n", status);
		return -1;
	}

    unsigned char raw_signature[SIGNATURE_BYTES];
    size_t raw_signature_length;

    ret = mbedtls_ecdsa_der_to_raw(
        CURVE_BITS,
        signature_contents,
        signature_contents_length,
        raw_signature,
        SIGNATURE_BYTES,
        &raw_signature_length
    );
    if (ret != 0) {
        printf("mbedtls_ecdsa_der_to_raw failed! (Error: %d %x)\n", ret, -ret);
		return -1;
    }

    print_hex(raw_signature, raw_signature_length);
    
    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );

    printf("Public pem:\n%s\n", public_pem);

    printf("Public key sizeof: %ld\n", public_pem_len);

    /*
     * Read the public key from disk
     */
    if( ( ret = mbedtls_pk_parse_public_key( &pk, public_pem, public_pem_len) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parse_public_key returned -0x%04x %d\n", -ret, ret );
        return -1;
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_ECDSA)) {
        printf(" failed\n  ! Key is not an ECDSA key\n");
        return -1;
    }


    mbedtls_ecdsa_context ctx_verify;
    mbedtls_ecdsa_init(&ctx_verify);

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    // We can only specify one key usage on mbedtls_pk_get_psa_attributes but then we can
    // change the attributes later to allow verifying both messages and hashes.
    ret = mbedtls_pk_get_psa_attributes(&pk, PSA_KEY_USAGE_VERIFY_MESSAGE, &attributes);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH);

    psa_key_id_t key_id;
    ret = mbedtls_pk_import_into_psa(&pk, &attributes, &key_id);
    if (ret != 0) {
        printf("Failed to import key (Error: %d %X)\n", ret, ret);
        return -1;
    }
    mbedtls_pk_free(&pk);

    fflush(stdout);

    size_t output_len;
    static uint8_t m_hash[32];

    status = psa_hash_compute(PSA_ALG_SHA_256,
				  signme_contents,
				  signme_contents_length,
				  m_hash,
				  sizeof(m_hash),
				  &output_len);
	if (status != PSA_SUCCESS) {
		printf("psa_hash_compute failed! (Error: %d)", status);
		return -1;
	}

    printf("SHA256 hash: ");
    int i;
    for (i = 0; i < 32; i++) {
        printf("%02x", m_hash[i]);
    }
    printf("\n");

    status = psa_verify_hash(
        key_id,
        PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
        m_hash,
        32,
        raw_signature,
        SIGNATURE_BYTES
    );

    if (status != PSA_SUCCESS) {
		printf("psa_verify_hash failed! (Error: %d)\n", status);
		return -1;
	}

    status = psa_verify_message(
        key_id,
        PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
        signme_contents,
        signme_contents_length,
        raw_signature,
        SIGNATURE_BYTES
    );

    if (status != PSA_SUCCESS) {
		printf("psa_verify_message failed! (Error: %d)\n", status);
		return -1;
	}

	printf("Signature verification was successful!");

    return 0;
}
