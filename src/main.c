#include "utils.c"
#include "psa/crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/psa_util.h"

// ** Change ** to be the directory where you've run the openssl commands
// (We can make this a build property later)
#define SIGFILES_DIRECTORY "/Users/db/GitHub/mbedtlsplay/sigfiles/"

#define PUBLIC_KEYFILE SIGFILES_DIRECTORY "public.pem"
#define SIGNME_TXT SIGFILES_DIRECTORY "signme.txt"
#define SIGNATURE_BIN SIGFILES_DIRECTORY "signature.bin"

#define CURVE_BITS 521
// 521 bits is 66 bytes rounded up and we need 2 values in the signature
#define SIGNATURE_BYTES 132

// Defined later in the file. Read DER-formatted (ASN.1) signature file `signature.bin`
// and content to sign in file `signme.txt`
uint8_t* read_signature_der_formatted(size_t* length);
uint8_t* read_signme(size_t* length);

int main() {
    psa_status_t status;
    int ret = 0;

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		printf("psa_crypto_init failed! (Error: %d)\n", status);
		return -1;
	}

    size_t signme_contents_length;
    uint8_t* signme_contents = read_signme(&signme_contents_length);
    printf("Signme contents length [%zu]: %s\n", signme_contents_length, signme_contents);

    size_t signature_contents_length;
    uint8_t* signature_contents = read_signature_der_formatted(&signature_contents_length);
    printf("Signature binary length: %zu\n", signature_contents_length);

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

    /*
     * Read the public key from disk
     */
    if( ( ret = mbedtls_pk_parse_public_keyfile( &pk, PUBLIC_KEYFILE ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", -ret );
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

uint8_t* read_signature_der_formatted(size_t* length) {
    FILE *f = fopen(SIGNATURE_BIN, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  /* same as rewind(f); */

    uint8_t* string = malloc(fsize);
    fread(string, fsize, 1, f);
    fclose(f);

    *length = fsize;

    return string;
}

uint8_t* read_signme(size_t* length) {
    FILE *f = fopen(SIGNME_TXT, "r");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);  /* same as rewind(f); */

    uint8_t* string = malloc(fsize + 1);
    fread(string, fsize, 1, f);
    fclose(f);
    string[fsize] = 0; // string terminator

    // Tack the null terminator on the end so that we can print this string
    // out but return the length without the null terminator character.
    *length = fsize;

    return string;
}
