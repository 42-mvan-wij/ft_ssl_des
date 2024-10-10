#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "random.h"

typedef __uint128_t uint128_t;

static uint64_t mod_pow(uint64_t base, uint64_t exponent, uint64_t modulus) {
	uint128_t b = base % modulus;
	uint128_t result = 1;
	while (exponent > 0) {
		if ((exponent & 1) == 1) {
			result = (result * b) % modulus;
		}
		exponent >>= 1;
		b = (b * b) % modulus;
	}
	return result;
}

bool composite_by_miller_rabin(uint64_t n, size_t rounds) {
	assert(n >= 2);
	// write(STDERR_FILENO, "^", 1);
	if (n == 2) {
		return false;
	}
	if ((n & 1) == 0) {
		return true;
	}
	// write(STDERR_FILENO, "/", 1);

	uint8_t s = 0;
	uint64_t d = n - 1;
	while ((d & 1) == 0) {
		s += 1;
		d >>= 1;
	}
	while (rounds > 0) {
		rounds--;

		uint64_t a = rand_in_range_inclusive(2, n - 2);

		uint64_t x = mod_pow(a, d, n);

		uint64_t y;
		for (uint8_t si = 0; si < s; si++) {
			y = mod_pow(x, 2, n);
			if (y == 1 && x != 1 && x != n - 1) {
				return true;
			}
			x = y;
		}
		if (y != 1) {
			return true;
		}
		write(STDERR_FILENO, "+", 1);
	}
	return false;
}
