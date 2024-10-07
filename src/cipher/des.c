#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "endian.h"
#include "error.h"
#include "utils.h"
#include "des.h"

static bool has_bit_reverse(uint64_t n, uint8_t bit_index) {
	return ((n >> bit_index) & 1) == 1;
}

static uint64_t set_bit_reverse(uint64_t original, uint8_t bit_index) {
	return original | ((uint64_t)1 << bit_index);
}

// static uint64_t clear_bit_reverse(uint64_t original, uint8_t bit_index) {
// 	return ~set_bit_reverse(~original, bit_index);
// }

// // FIXME: remove
// #include <stdio.h>
// static void print_binary(uint64_t n, uint8_t spacing, uint8_t skip_bits, uint8_t num_bits) {
// 	for (size_t i = 0; i < num_bits; i++) {
// 		size_t index = i + skip_bits;
// 		printf("%c", ((n >> (64 - index - 1)) & 1) == 1 ? '1' : '0');
// 		if (spacing != 0 && i != num_bits - 1 && i % spacing == spacing - 1) {
// 			printf(" ");
// 		}
// 	}
// }
// static void print_binary_reverse(uint64_t n, uint8_t spacing, uint8_t skip_bits, uint8_t num_bits) {
// 	(void)skip_bits;
// 	// [0..64];
// 	// [skip_bits..skip_bits+num_bits];
// 	for (size_t i = 0; i < num_bits; i++) {
// 		size_t index = skip_bits+num_bits-i-1;
// 		printf("%c", ((n >> (64 - index - 1)) & 1) == 1 ? '1' : '0');
// 		if (spacing != 0 && i != num_bits - 1 && i % spacing == spacing - 1) {
// 			printf(" ");
// 		}
// 	}
// }

static uint32_t f(uint32_t r, uint64_t k) {
	// NOTE: r is reverse
	// NOTE: k is 48 bit reverse
	static uint8_t const e[] = {
		32,  1,  2,  3,  4,  5,
		 4,  5,  6,  7,  8,  9,
		 8,  9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32,  1,
	};

	static uint8_t const s1[] = { // NOTE: 4 bit
		14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
		 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
		 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
		15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
	};
	static uint8_t const s2[] = { // NOTE: 4 bit
		15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
		 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
		 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
		13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
	};
	static uint8_t const s3[] = { // NOTE: 4 bit
		10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
		13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
		13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
		 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
	};
	static uint8_t const s4[] = { // NOTE: 4 bit
		 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
		13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
		10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
		 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
	};
	static uint8_t const s5[] = { // NOTE: 4 bit
		 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
		14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
		 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
		11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
	};
	static uint8_t const s6[] = { // NOTE: 4 bit
		12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
		10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
		 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
		 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
	};
	static uint8_t const s7[] = { // NOTE: 4 bit
		 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
		13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
		 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
		 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
	};
	static uint8_t const s8[] = { // NOTE: 4 bit
		13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
		 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
		 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
		 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11,
	};
	static uint8_t const * const s_tables[] = {
		s1, s2, s3, s4, s5, s6, s7, s8,
	};
	static uint8_t const s_row_length = lengthof(s1) / 4;
	static uint8_t const p[] = {
		16,  7, 20, 21,
		29, 12, 28, 17,
		 1, 15, 23, 26,
		 5, 18, 31, 10,
		 2,  8, 24, 14,
		32, 27,  3,  9,
		19, 13, 30,  6,
		22, 11,  4, 25,
	};

	uint64_t rr = 0; // NOTE: 48 bit reverse
	for (size_t bit_index = 0; bit_index < lengthof(e); bit_index++) {
		if (has_bit_reverse(r, e[bit_index] - 1)) {
			rr = set_bit_reverse(rr, bit_index);
		}
	}

	uint64_t xorred = rr ^ k; // NOTE: 48 bit reverse

	uint32_t out = 0; // NOTE: reverse
	for (size_t block_index = 0; block_index < 48 / 6; block_index++) {
		uint8_t b = (xorred >> block_index * 6) & 0b111111; // NOTE: 6 bit reverse
		uint8_t row = (b & 1) << 1 | ((b >> 5) & 1); // NOTE: 2 bit
		uint8_t col = ((b >> 1) & 1) << 3 | ((b >> 2) & 1) << 2 | ((b >> 3) & 1) << 1 | ((b >> 4) & 1); // NOTE: 4 bit

		size_t index = row * s_row_length + col;
		uint8_t a = s_tables[block_index][index]; // NOTE: 4 bit
		uint8_t rev_a = (a & 1) << 3 | ((a >> 1) & 1) << 2 | ((a >> 2) & 1) << 1 | ((a >> 3) & 1); // NOTE: 4 bit reverse

		out |= (uint64_t)rev_a << block_index * 4;
	}

	uint32_t permuted_out = 0; // NOTE: reverse
	for (size_t bit_index = 0; bit_index < lengthof(p); bit_index++) {
		if (has_bit_reverse(out, p[bit_index] - 1)) {
			permuted_out = set_bit_reverse(permuted_out, bit_index);
		}
	}
	return permuted_out;
}

static void generate_sub_keys(uint64_t key, uint64_t *sub_keys) {
	static uint8_t const pc1[] = {
		57, 49, 41, 33, 25, 17,  9,
		 1, 58, 50, 42, 34, 26, 18,
		10,  2, 59, 51, 43, 35, 27,
		19, 11,  3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		 7, 62, 54, 46, 38, 30, 22,
		14,  6, 61, 53, 45, 37, 29,
		21, 13,  5, 28, 20, 12,  4,
	};
	static uint8_t const k_shifts[] = {
		1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
	};
	static uint8_t const pc2[] = {
		14, 17, 11, 24,  1,  5,
		 3, 28, 15,  6, 21, 10,
		23, 19, 12,  4, 26,  8,
		16,  7, 27, 20, 13,  2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32,
	};

	uint64_t k_plus = 0; // NOTE: 56 bit reverse
	for (size_t bit_index = 0; bit_index < lengthof(pc1); bit_index++) {
		if (has_bit_reverse(key, 64 - pc1[bit_index])) { // NOTE: we store k_plus in reverse order
			k_plus = set_bit_reverse(k_plus, bit_index);
		}
	}

	uint32_t k_plus_left = k_plus & ((1 << 28) - 1); // NOTE: 28 bit reverse
	uint32_t k_plus_right = (k_plus >> 28) & ((1 << 28) - 1); // NOTE: 28 bit reverse

	uint32_t k_left[16]; // NOTE: 28 bit reverse
	uint32_t k_right[16]; // NOTE: 28 bit reverse
	k_left[0] = circular_right_shift_bits(k_plus_left, 1, 28);
	k_right[0] = circular_right_shift_bits(k_plus_right, 1, 28);
	for (size_t i = 1; i < lengthof(k_left); i++) {
		k_left[i] = circular_right_shift_bits(k_left[i - 1], k_shifts[i - 1], 28);
		k_right[i] = circular_right_shift_bits(k_right[i - 1], k_shifts[i - 1], 28);
	}

	for (size_t i = 0; i < 16; i++) {
		uint64_t joined = (uint64_t)k_right[i] << 28 | k_left[i]; // NOTE: 56 bit reverse
		for (size_t bit_index = 0; bit_index < lengthof(pc2); bit_index++) {
			if (has_bit_reverse(joined, pc2[bit_index] - 1)) {
				sub_keys[i] = set_bit_reverse(sub_keys[i], bit_index);
			}
		}
	}
}

static uint64_t permute_msg(uint64_t msg) {
	static uint8_t const ip[] = {
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17,  9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7,
	};

	uint64_t m_plus = 0; // NOTE: reverse
	for (size_t bit_index = 0; bit_index < lengthof(ip); bit_index++) {
		if (has_bit_reverse(msg, 64 - ip[bit_index])) {
			m_plus = set_bit_reverse(m_plus, bit_index);
		}
	}
	return m_plus;
}

static uint64_t generate_encode_rl(uint64_t m_plus, uint64_t *keys) {
	uint32_t m_plus_left = m_plus & 0xFFFFFFFF; // NOTE: reverse
	uint32_t m_plus_right = m_plus >> 32; // NOTE: reverse

	uint32_t m_left[16]; // NOTE: reverse
	uint32_t m_right[16]; // NOTE: reverse
	m_left[0] = m_plus_right;
	m_right[0] = m_plus_left ^ f(m_plus_right, keys[0]);
	for (size_t i = 1; i < 16; i++) {
		m_left[i] = m_right[i - 1];
		m_right[i] = m_left[i - 1] ^ f(m_right[i - 1], keys[i]);
	}

	uint64_t rl = (uint64_t)m_left[15] << 32 | m_right[15]; // NOTE: reverse
	return rl;
}

static uint64_t generate_decode_rl(uint64_t m_plus, uint64_t *keys) {
	uint32_t m_plus_left = m_plus & 0xFFFFFFFF; // NOTE: reverse
	uint32_t m_plus_right = m_plus >> 32; // NOTE: reverse

	uint32_t m_left[16]; // NOTE: reverse
	uint32_t m_right[16]; // NOTE: reverse
	m_left[0] = m_plus_right;
	m_right[0] = m_plus_left ^ f(m_plus_right, keys[15]);
	for (size_t i = 1; i < 16; i++) {
		m_left[i] = m_right[i - 1];
		m_right[i] = m_left[i - 1] ^ f(m_right[i - 1], keys[16 - i - 1]);
	}

	uint64_t rl = (uint64_t)m_left[15] << 32 | m_right[15]; // NOTE: reverse
	return rl;
}

static uint64_t unpermute_rl(uint64_t rl) {
	static uint8_t const ip_prime[] = {
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41,  9, 49, 17, 57, 25,
	};

	uint64_t q = 0;
	for (size_t bit_index = 0; bit_index < lengthof(ip_prime); bit_index++) {
		if (has_bit_reverse(rl, ip_prime[bit_index] - 1)) {
			q = set_bit_reverse(q, 64 - bit_index - 1);
		}
	}
	return q;
}

static uint64_t des_encode_block(uint64_t block, uint64_t key) {
	uint64_t k[16] = {0}; // NOTE: 48 bit reverse
	generate_sub_keys(key, k);
	uint64_t m_plus = permute_msg(block);
	uint64_t rl = generate_encode_rl(m_plus, k);
	return unpermute_rl(rl);
}

static uint64_t des_decode_block(uint64_t block, uint64_t key) {
	uint64_t k[16] = {0}; // NOTE: 48 bit reverse
	generate_sub_keys(key, k);
	uint64_t m_plus = permute_msg(block);
	uint64_t rl = generate_decode_rl(m_plus, k);
	return unpermute_rl(rl);
}

// static uint64_t des_encode_blocks(uint64_t const *blocks, size_t num_blocks, uint64_t key) {
//
// 	size_t i = 0;
// 	while (i < num_blocks) {
// 		uint64_t block = blocks[i];
// 		// uint32_t left = block >> 32;
// 		// uint32_t right = block; // use integer truncation
// 		// uint32_t right = block & UINT32_MAX;
//
// 		uint64_t encoded = des_encode_block(block, key);
//
//
// 		i++;
// 	}
// }
// static void des_encode_final_block(uint8_t const *buf, size_t len) {
// }

#include <stdio.h>
void des_test(void) {
	uint64_t msg = 0x0123456789ABCDEF;
	uint64_t key = 0x133457799BBCDFF1;
	uint64_t encoded = des_encode_block(msg, key);
	printf("(%.16lx, %.16lx) => %.16lx\n", msg, key, encoded);
	uint64_t decoded = des_decode_block(encoded, key);
	printf("%.16lx <= (%.16lx, %.16lx)\n", decoded, encoded, key);
}

// void des_decode_buf(uint8_t const *buf, size_t buf_size, char *out_buf);
// uint8_t *des_decode_fd(int fd, size_t *num_octets);
// void des_encode_buf(uint8_t const *buf, size_t buf_size, char *out_buf);
// char *des_encode_fd(int fd);

// size_t des_encode_len(size_t num_bits, size_t include_padding);
// size_t des_decode_len_octets(size_t encoded_len, size_t padding_len);
void des_ecb_encode_buf(void const *buf, size_t buf_size, uint8_t const key[8], void *out_buf) {
	uint64_t const *buf_64 = buf;
	uint64_t const *k64 = (void const *)key;
	uint64_t k = BIG_TO_HOST_ENDIAN(uint64_t, k64[0]);
	uint8_t *out_buf_bytes = out_buf;
	size_t offset = 0;
	while (buf_size - offset >= sizeof(uint64_t)) {
		uint64_t v = BIG_TO_HOST_ENDIAN(uint64_t, buf_64[offset / sizeof(uint64_t)]);
		uint64_t e = HOST_TO_BIG_ENDIAN(uint64_t, des_encode_block(v, k));
		ft_memcpy(out_buf_bytes + offset, &e, sizeof(e));
		offset += sizeof(e);
	}

	uint64_t final_block;
	{
		uint8_t *f_8 = (void*)&final_block;
		uint8_t const *buf_8 = buf;
		ft_memcpy(&final_block, buf_8 + offset, buf_size - offset);
		uint8_t pad = 8 - (buf_size - offset);
		for (uint8_t i = 0; i < pad; i++) {
			f_8[8 - pad + i] = pad;
		}
	}
	uint64_t v = BIG_TO_HOST_ENDIAN(uint64_t, final_block);
	uint64_t e = HOST_TO_BIG_ENDIAN(uint64_t, des_encode_block(v, k));
	ft_memcpy(out_buf_bytes + offset, &e, sizeof(e));
}

char *des_ecb_encode_fd(int fd, uint8_t const key[8], size_t *size) {
	size_t in_size;
	char *s = read_to_string(fd, &in_size);
	if (s == NULL) {
		return retain_error_null(NULL);
	}
	*size = ((in_size / 8) + 1) * 8;
	void *out_buf = malloc(sizeof(char) * (*size));
	if (out_buf == NULL) {
		return set_error_null(E_ERRNO, NULL);
	}
	des_ecb_encode_buf(s, in_size, key, out_buf);
	free(s);
	return out_buf;
}

t_result des_ecb_decode_buf(void const *buf, size_t buf_size, uint8_t const key[8], void *out_buf, size_t *real_length) {
	if (buf_size % 8 != 0 || buf_size == 0) {
		return set_error(E_INVALID_LENGTH, "Invalid block length");
	}
	uint64_t const *buf_64 = buf;
	uint64_t const *k64 = (void const *)key;
	uint64_t k = BIG_TO_HOST_ENDIAN(uint64_t, k64[0]);
	uint8_t *out_buf_bytes = out_buf;
	size_t offset = 0;
	while (buf_size - offset >= sizeof(uint64_t)) {
		uint64_t v = BIG_TO_HOST_ENDIAN(uint64_t, buf_64[offset / sizeof(uint64_t)]);
		uint64_t e = HOST_TO_BIG_ENDIAN(uint64_t, des_decode_block(v, k));
		ft_memcpy(out_buf_bytes + offset, &e, sizeof(e));
		offset += sizeof(e);
	}
	uint8_t padding = out_buf_bytes[buf_size - 1];
	if (padding == 0 || padding > 8) {
		return set_error(E_DES_BAD_BLOCK, "Bad block");
	}
	for (uint8_t i = 1; i < padding; i++) {
		if (out_buf_bytes[buf_size - 1 - i] != padding) {
			return set_error(E_DES_BAD_BLOCK, "Bad block");
		}
	}
	*real_length = buf_size - out_buf_bytes[buf_size - 1];
	return OK;
}

char *des_ecb_decode_fd(int fd, uint8_t const key[8], size_t *size) {
	size_t in_size;
	char *s = read_to_string(fd, &in_size);
	if (s == NULL) {
		return retain_error_null(NULL);
	}
	if (in_size % 8 != 0) {
		return set_error_null(E_INVALID_LENGTH, "Invalid block length");
	}
	void *out_buf = malloc(sizeof(char) * (in_size));
	if (out_buf == NULL) {
		return set_error_null(E_ERRNO, NULL);
	}
	if (des_ecb_decode_buf(s, in_size, key, out_buf, size) != OK) {
		free(s);
		free(out_buf);
		return retain_error_null(NULL);
	}
	free(s);
	return out_buf;
}

void des_cbc_encode_buf(void const *buf, size_t buf_size, uint8_t const key[8], uint8_t const iv[8], void *out_buf) {
	uint64_t iv_; {
		ft_memcpy(&iv_, iv, sizeof(iv_));
		iv_ = BIG_TO_HOST_ENDIAN(uint64_t, iv_);
	}

	uint64_t const *buf_64 = buf;
	uint64_t const *k64 = (void const *)key;
	uint64_t k = BIG_TO_HOST_ENDIAN(uint64_t, k64[0]);
	uint8_t *out_buf_bytes = out_buf;
	size_t offset = 0;
	while (buf_size - offset >= sizeof(uint64_t)) {
		uint64_t v = BIG_TO_HOST_ENDIAN(uint64_t, buf_64[offset / sizeof(uint64_t)]) ^ iv_;
		iv_ = des_encode_block(v, k);
		uint64_t e = HOST_TO_BIG_ENDIAN(uint64_t, iv_);
		ft_memcpy(out_buf_bytes + offset, &e, sizeof(e));
		offset += sizeof(e);
	}

	uint64_t padded_final_block; {
		uint8_t *f_8 = (void*)&padded_final_block;
		uint8_t const *buf_8 = buf;
		ft_memcpy(&padded_final_block, buf_8 + offset, buf_size - offset);
		uint8_t pad = 8 - (buf_size - offset);
		for (uint8_t i = 0; i < pad; i++) {
			f_8[8 - pad + i] = pad;
		}
	}
	uint64_t v = BIG_TO_HOST_ENDIAN(uint64_t, padded_final_block) ^ iv_;
	uint64_t e = HOST_TO_BIG_ENDIAN(uint64_t, des_encode_block(v, k));
	ft_memcpy(out_buf_bytes + offset, &e, sizeof(e));
}

char *des_cbc_encode_fd(int fd, uint8_t const key[8], uint8_t const iv[8], size_t *size) {
	size_t in_size;
	char *s = read_to_string(fd, &in_size);
	if (s == NULL) {
		return retain_error_null(NULL);
	}
	*size = ((in_size / 8) + 1) * 8;
	void *out_buf = malloc(sizeof(char) * (*size));
	if (out_buf == NULL) {
		return set_error_null(E_ERRNO, NULL);
	}
	des_cbc_encode_buf(s, in_size, key, iv, out_buf);
	free(s);
	return out_buf;
}

t_result des_cbc_decode_buf(void const *buf, size_t buf_size, uint8_t const key[8], uint8_t const iv[8], void *out_buf, size_t *real_length) {
	if (buf_size % 8 != 0 || buf_size == 0) {
		return set_error(E_INVALID_LENGTH, "Invalid block length");
	}

	uint64_t iv_; {
		ft_memcpy(&iv_, iv, sizeof(iv_));
		iv_ = BIG_TO_HOST_ENDIAN(uint64_t, iv_);
	}

	uint64_t const *buf_64 = buf;
	uint64_t const *k64 = (void const *)key;
	uint64_t k = BIG_TO_HOST_ENDIAN(uint64_t, k64[0]);
	uint8_t *out_buf_bytes = out_buf;
	size_t offset = 0;
	while (buf_size - offset >= sizeof(uint64_t)) {
		uint64_t v = BIG_TO_HOST_ENDIAN(uint64_t, buf_64[offset / sizeof(uint64_t)]);
		uint64_t e = HOST_TO_BIG_ENDIAN(uint64_t, des_decode_block(v, k) ^ iv_);
		iv_ = v;
		ft_memcpy(out_buf_bytes + offset, &e, sizeof(e));
		offset += sizeof(e);
	}
	uint8_t padding = out_buf_bytes[buf_size - 1];
	if (padding == 0 || padding > 8) {
		return set_error(E_DES_BAD_BLOCK, "Bad block");
	}
	for (uint8_t i = 1; i < padding; i++) {
		if (out_buf_bytes[buf_size - 1 - i] != padding) {
			return set_error(E_DES_BAD_BLOCK, "Bad block");
		}
	}
	*real_length = buf_size - out_buf_bytes[buf_size - 1];
	return OK;
}

char *des_cbc_decode_fd(int fd, uint8_t const key[8], uint8_t const iv[8], size_t *size) {
	size_t in_size;
	char *s = read_to_string(fd, &in_size);
	if (s == NULL) {
		return retain_error_null(NULL);
	}
	if (in_size % 8 != 0) {
		return set_error_null(E_INVALID_LENGTH, "Invalid block length");
	}
	void *out_buf = malloc(sizeof(char) * (in_size));
	if (out_buf == NULL) {
		return set_error_null(E_ERRNO, NULL);
	}
	if (des_cbc_decode_buf(s, in_size, key, iv, out_buf, size) != OK) {
		free(s);
		free(out_buf);
		return retain_error_null(NULL);
	}
	free(s);
	return out_buf;
}

// void create_stream(void) {
// 	struct a a = (struct a){
// 		.name = "birb",
// 	};
//
// 	return a;
// }
//
// void stream_data(struct a *a, void const *b, size_t size) {
// 	size_t remaining = sizeof(a->buf) - a->buf_len;
// 	size_t copy = size > remaining ? remaining : size;
// 	ft_memcpy(a->buf + a->buf_len, b, size);
// 	a->buf_len += copy;
// 	size_t offset = copy;
// 	if (a->buf_len >= sizeof(a->buf)) {
// 		__apply_some_func__(a->buf);
// 		a->buf_len = 0;
//
// 		while (size - offset > sizeof(a->buf)) {
// 			__apply_some_func__(buf + offset);
// 			offset += sizeof(a->buf);
// 		}
// 		if (size - offset > 0) {
// 			ft_memcpy(a->buf, buf, size - offset);
// 			a->buf_len = size - offset;
// 		}
// 	}
// }
//
// void stream_finish(void) {
// 	__apply_some_final_func__(a->buf, a->buf_len);
// }

