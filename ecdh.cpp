#include <cstring>
#include <sdkconfig.h>
#include <stdlib.h>
#include <esp_log.h>
#ifdef CONFIG_IDF_TARGET_ESP8266
	#include <esp_system.h>
#else
	#include <esp_random.h>
	#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md5.h>
#include <mbedtls/platform_util.h>

#include "ecdh.h"

#define ERROR_CHECK(ret) { if (ret != 0) { ESP_LOGE(TAG, "error: %x line:%d", ret, __LINE__); abort(); } }

static void flip_endian(uint8_t *data, size_t len) {
    uint8_t swp_buf;
    for (int i = 0; i < len/2; i++) {
        swp_buf = data[i];
        data[i] = data[len - i - 1];
        data[len - i - 1] = swp_buf;
    }
}

static int get_randoms(void *p_rng, unsigned char *output, size_t output_len) {
	esp_fill_random(output, output_len);
	return 0;
}

void Ecdh::generateKeypair(const uint8_t* entropy_data, const size_t entropy_data_len) {
	mbedtls_ecp_group ecp_group;
	mbedtls_ecp_group_init(&ecp_group);
	ERROR_CHECK(mbedtls_ecp_group_load(&ecp_group, ECDH_CURVE));

	mbedtls_mpi a;
	mbedtls_mpi_init(&a);
	mbedtls_ecp_point A;
	mbedtls_ecp_point_init(&A);
	ERROR_CHECK(mbedtls_ecp_gen_keypair(&ecp_group, &a, &A, get_randoms, nullptr));
	ERROR_CHECK(mbedtls_mpi_write_binary(&a, this->private_key, ECDH_KEY_SIZE));
	this->writePublicKey(&A, this->public_key);

	mbedtls_ecp_group_free(&ecp_group);
	mbedtls_mpi_free(&a);
	mbedtls_ecp_point_free(&A);
}

bool Ecdh::generateSharedSecret(const uint8_t* public_key, uint8_t* shared_secret) {
	mbedtls_ecp_group ecp_group;
	mbedtls_ecp_group_init(&ecp_group);
	ERROR_CHECK(mbedtls_ecp_group_load(&ecp_group, ECDH_CURVE));

	mbedtls_ecp_point B;
	mbedtls_ecp_point_init(&B);
	this->readPublicKey(public_key, &B);
	if (mbedtls_ecp_check_pubkey(&ecp_group, &B) != 0) {
		ESP_LOGE(TAG, "Invalid public key");
		return false;
	}

	mbedtls_mpi a;
	mbedtls_mpi_init(&a);
	ERROR_CHECK(mbedtls_mpi_read_binary(&a, this->private_key, ECDH_KEY_SIZE));

	mbedtls_ecp_point S;
	mbedtls_ecp_point_init(&S);
	ERROR_CHECK(mbedtls_ecp_mul(&ecp_group, &S, &a, &B, get_randoms, nullptr));

	uint8_t S_bytes[ECDH_KEY_SIZE];
	this->writePublicKey(&S, S_bytes);

	mbedtls_md5_context md5;
	mbedtls_md5_init(&md5);
	mbedtls_md5_starts(&md5);
	mbedtls_md5_update(&md5, S_bytes, ECDH_KEY_SIZE);
	mbedtls_md5_finish(&md5, shared_secret);


	mbedtls_ecp_group_free(&ecp_group);
	mbedtls_mpi_free(&a);
	mbedtls_ecp_point_free(&B);
	mbedtls_ecp_point_free(&S);
	mbedtls_md5_free(&md5);

	mbedtls_platform_zeroize(S_bytes, sizeof(S_bytes));

	return true;
}

void Ecdh::writePublicKey(const mbedtls_ecp_point* pk, uint8_t* data) {
	ERROR_CHECK(mbedtls_mpi_write_binary(&(pk->X), data, ECDH_KEY_SIZE));
	if (ECDH_CURVE == MBEDTLS_ECP_DP_CURVE25519) {
		flip_endian(data, ECDH_KEY_SIZE); // CURVE25519 is little endian
	}
}

void Ecdh::readPublicKey(const uint8_t* data, mbedtls_ecp_point* pk) {
	uint8_t public_key_copy[ECDH_KEY_SIZE];
	memcpy(public_key_copy, data, sizeof(public_key_copy));
	flip_endian(public_key_copy, sizeof(public_key_copy));
	ERROR_CHECK(mbedtls_mpi_read_binary(&(pk->X), public_key_copy, ECDH_KEY_SIZE));
	if (ECDH_CURVE == MBEDTLS_ECP_DP_CURVE25519) {
		/* Set most significant bit to 0 as prescribed in RFC7748 §5 */
		ERROR_CHECK(mbedtls_mpi_set_bit(&(pk->X), ECDH_KEY_SIZE * 8 - 1, 0));
	}
	ERROR_CHECK(mbedtls_mpi_lset(&(pk->Z), 1));
}
