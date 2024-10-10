#include <stdbool.h>
#include <stdint.h>

typedef __uint128_t uint128_t;

uint64_t gcd(uint64_t a, uint64_t b) {
	while (a != b && b != 0) {
		a %= b;
		uint64_t tmp = a;
		a = b;
		b = tmp;
	}
	return a;
}

uint64_t lcm(uint32_t a, uint32_t b) {
	return ((uint64_t)a * b) / gcd(a, b);
}

uint64_t mod_mult_inverse(uint64_t n, uint64_t modulus) {
	uint64_t even_r = n;
	uint64_t odd_r = modulus;

	uint64_t even_s = 1;
	uint64_t odd_s = 0;

	while (true) {
		uint64_t q = even_r / odd_r;

		even_r = even_r - q * odd_r;
		if (even_r == 0) {
			return modulus - odd_s;
		}
		even_s = even_s + q * odd_s;

		q = odd_r / even_r;

		odd_r = odd_r - q * even_r;
		if (odd_r == 0) {
			return even_s;
		}
		odd_s = odd_s + q * even_s;
	}
}
