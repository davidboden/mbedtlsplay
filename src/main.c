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

#define PUBLIC_KEYFILE SIGFILES_DIRECTORY "public256.pem"
#define SIGNME_TXT SIGFILES_DIRECTORY "signme.txt"
#define SIGNATURE_BIN SIGFILES_DIRECTORY "signature256.bin"
#define PUBLIC_KEY_RAW_OUTPUT SIGFILES_DIRECTORY "public256.raw"
#define SIGNATURE_RAW_OUTPUT SIGFILES_DIRECTORY "signature256.raw"

#define CURVE_BITS 256
// 256 bits is 32 bytes and we need 2 values in the signature
#define SIGNATURE_BYTES 64

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

// Loads public key PEM and signature DER from disk and writes them
// in raw format. The raw format is need for the PSA library.
// Later, we use the xxd -i utility to copy/paste the raw byte arrays
// into this source file and use the raw versions to perform the
// digital signature verification.
int load_and_write() {
    size_t signature_contents_length;
    uint8_t* signature_contents = read_signature_der_formatted(&signature_contents_length);
    printf("Signature binary length: %zu\n", signature_contents_length);

    unsigned char raw_signature[SIGNATURE_BYTES];
    size_t raw_signature_length;

    int ret = mbedtls_ecdsa_der_to_raw(
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

    // print_hex(raw_signature, raw_signature_length);

    FILE* signatureRawFileToWrite;
    if((signatureRawFileToWrite = fopen(SIGNATURE_RAW_OUTPUT, "wb+")) != NULL){
        fwrite(raw_signature, 1, raw_signature_length, signatureRawFileToWrite);
        fclose(signatureRawFileToWrite);
    }

    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );

    /*
     * Read the public key from disk
     */
    if( ( ret = mbedtls_pk_parse_public_keyfile( &pk, PUBLIC_KEYFILE ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x %d\n", -ret, ret );
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

    uint8_t exported_key[2048];
    size_t exported_key_length;

    psa_status_t status = psa_export_public_key(
        key_id,
        exported_key,
        2048,
        &exported_key_length
    );

    if (status != PSA_SUCCESS) {
		printf("psa_export_public_key failed! (Error: %d)\n", status);
		return -1;
	}

    FILE* publicKeyRawFileToWrite;
    if((publicKeyRawFileToWrite = fopen(PUBLIC_KEY_RAW_OUTPUT, "wb+")) != NULL){
        fwrite(exported_key, 1, exported_key_length, publicKeyRawFileToWrite);
        fclose(publicKeyRawFileToWrite);
    }

    return 0;
}

int main() {
    psa_status_t status;
    int ret = 0;

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
	if (status != PSA_SUCCESS) {
		printf("psa_crypto_init failed! (Error: %d)\n", status);
		return -1;
	}

    ret = load_and_write();
    if (ret != 0) {
        printf("Load and write failed: %d", ret);
        return -1;
    }

    // Copy & pasted from signme.txt
    unsigned char signme_contents[] = "Hello world sign me\n";
    unsigned int signme_contents_length = sizeof(signme_contents) - 1; // Don't consider the null terminator

    unsigned char public256_raw[] = {
    0x04, 0x54, 0xd7, 0x91, 0xf5, 0x47, 0x26, 0x2f, 0xb1, 0x4b, 0x5d, 0xc2,
    0xc7, 0xec, 0x84, 0x29, 0x90, 0x0d, 0x77, 0x46, 0x72, 0x99, 0xc6, 0xe1,
    0x03, 0xf0, 0x4c, 0x09, 0xe1, 0xab, 0x81, 0xd1, 0x8d, 0xc9, 0xea, 0x7e,
    0x4f, 0x1a, 0xc4, 0xed, 0x30, 0xf1, 0x9e, 0x1d, 0x7b, 0xc9, 0x02, 0x9a,
    0x2c, 0x72, 0x94, 0xe8, 0x6a, 0x20, 0x62, 0x57, 0x3c, 0x94, 0xda, 0xb6,
    0x6a, 0x10, 0x78, 0xfe, 0x92
    };
    unsigned int public256_raw_len = 65;

    unsigned char signature256_raw[] = {
    0xd8, 0x37, 0xf8, 0x16, 0x54, 0x09, 0x4a, 0x29, 0xdc, 0x64, 0x49, 0xed,
    0xa9, 0x85, 0xde, 0x76, 0xd6, 0xc3, 0x33, 0x67, 0xc8, 0x5a, 0xe6, 0xae,
    0x1c, 0x22, 0xf9, 0xcd, 0x9f, 0xe1, 0x72, 0x9a, 0x23, 0xef, 0x08, 0xee,
    0xcb, 0x49, 0xd2, 0x9f, 0x3e, 0xb3, 0x82, 0xe5, 0xc2, 0x10, 0x72, 0x85,
    0x27, 0xdd, 0x2f, 0x4f, 0xd0, 0xcf, 0x9a, 0x95, 0x0f, 0x28, 0x2b, 0x8e,
    0x38, 0x74, 0x3f, 0xe0
    };
    unsigned int signature256_raw_len = 64;

    psa_key_id_t key2_id;
    psa_key_attributes_t attributes2 = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes2, PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_bits(&attributes2, CURVE_BITS);
    psa_set_key_type(&attributes2, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_algorithm(&attributes2, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_import_key(&attributes2, public256_raw, public256_raw_len, &key2_id);

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
        key2_id,
        PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        m_hash,
        32,
        signature256_raw,
        signature256_raw_len
    );

    if (status != PSA_SUCCESS) {
		printf("psa_verify_hash failed! (Error: %d)\n", status);
		return -1;
	}

    status = psa_verify_message(
        key2_id,
        PSA_ALG_ECDSA(PSA_ALG_SHA_256),
        signme_contents,
        signme_contents_length,
        signature256_raw,
        signature256_raw_len
    );

    if (status != PSA_SUCCESS) {
		printf("psa_verify_message failed! (Error: %d)\n", status);
		return -1;
	}

	printf("Signature verification was successful!");

    return 0;
}
