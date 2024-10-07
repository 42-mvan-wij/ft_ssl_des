#include "utils.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "error.h"

size_t ft_strlen(char const *str) {
	size_t len = 0;
	while (str[len] != '\0') {
		len++;
	}
	return len;
}

ssize_t ft_putstr(int fd, char const *str) {
	size_t len = ft_strlen(str);
	return write(fd, str, len);
}

// ssize_t ft_putendl(int fd, char *str) {
// 	size_t len = ft_strlen(str);
// 	str[len] = '\n';
// 	ssize_t ret = write(fd, str, len + 1);
// 	str[len] = '\0';
// 	return ret;
// }

int ft_strcmp(char const *s1, char const *s2) {
	size_t i = 0;
	while (s1[i] != '\0' && s1[i] == s2[i]) {// && s2[i] != '\0'
		i++;
	}
	return s1[i] - s2[i];
}

bool ft_streq(char const *s1, char const *s2) {
	return ft_strcmp(s1, s2) == 0;
}

bool ft_str_starts_with(char const *haystack, char const *start) {
	size_t i = 0;
	while (start[i] != '\0' && haystack[i] == start[i]) {// && haystack[i] != '\0'
		i++;
	}
	return (start[i] == '\0');
}

void ft_memset(void *buf, uint8_t byte_value, size_t size) {
	uint8_t *b = buf;
	size_t i = 0;
	while (i < size) {
		b[i] = byte_value;
		i++;
	}
}

bool ft_isprint(char c) {
	return c >= 32 && c <= 126;
}

bool should_be_escaped(char c) {
	return !ft_isprint(c) || c == '\\' || c == '"';
}

void print_escaped(int fd, char const *s, size_t len) {
	size_t index = 0;
	while (index < len) {
		if (should_be_escaped(s[index])) {
			char *escaped;
			char c = s[index];
			index++;
			switch (c) {
				case '\\': escaped = "\\\\"; break;
				case '"': escaped = "\\\""; break;
				case '\0': escaped = "\\0"; break;
				case '\t': escaped = "\\t"; break;
				case '\n': escaped = "\\n"; break;
				case '\v': escaped = "\\v"; break;
				case '\f': escaped = "\\f"; break;
				case '\r': escaped = "\\r"; break;
				default: {
					static char hex[] = "0123456789abcdef";
					unsigned char cc = (unsigned char)c;
					char ss[] = {'\\', hex[(cc / 16) % 16], hex[cc % 16]};
					write(fd, ss, 3);
					continue; // continue the loop, as to not print the other cases
					break;
				};
			}
			write(fd, escaped, 2);
		}
		else {
			size_t printable_len = 1;
			while (index + printable_len < len && !should_be_escaped(s[index + printable_len])) {
				printable_len++;
			}
			write(fd, &s[index], printable_len);
			index += printable_len;
		}
	}
}

// void ft_memcpy(void *dst, void *src, size_t size) {
// 	char *d = dst;
// 	char *s = src;
//
// 	size_t i = 0;
// 	while (i < size) {
// 		d[i] = s[i];
// 		i++;
// 	}
// }

void ft_memcpy(void *dst, void const *src, size_t size) {
	// uint64_t *d64 = dst;
	// uint64_t const *s64 = src;
	uint8_t *d = dst;
	uint8_t const *s = src;

	size_t i = 0;
	// while (i < size / sizeof(uint64_t)) {
	// 	d64[i] = s64[i];
	// 	i++;
	// }
	// i *= sizeof(uint64_t);
	while (i < size) {
		d[i] = s[i];
		i++;
	}
}

void *ft_realloc(void *p, size_t old_size, size_t new_size) {
	void *new_ptr = malloc(new_size);
	if (new_ptr == NULL) {
		free(p);
		return NULL;
	}
	ft_memcpy(new_ptr, p, old_size);
	free(p);
	return new_ptr;
}

char *ft_strdup(char const *str) {
	size_t len = ft_strlen(str);
	char *new_str = malloc(sizeof(char) * (len + 1));
	if (new_str == NULL) {
		return NULL;
	}
	ft_memcpy(new_str, str, len + 1);
	return new_str;
}

char *read_to_string(int fd, size_t *len) {
	size_t size = sizeof(char) * 64;
	size_t length = 0;
	char *s = malloc(size);
	if (s == NULL) {
		(void)set_error(E_ERRNO, NULL);
		return NULL;
	}
	while (true) {
		ssize_t nread = read(fd, s + length, size - (length + 1) * sizeof(char));
		if (nread < 0) {
			free(s);
			(void)set_error(E_ERRNO, NULL);
			return NULL;
		}
		if (nread == 0) {
			break;
		}
		length += nread;
		s = ft_realloc(s, size, size * 2);
		if (s == NULL) {
			(void)set_error(E_ERRNO, NULL);
			return NULL;
		}
		size *= 2;
	}
	s[length] = '\0';
	*len = length;
	return s;
}

__attribute__((no_sanitize("unsigned-shift-base")))
uint32_t circular_left_shift(uint32_t n, uint32_t shift_bits) {
	return ((n << shift_bits) | (n >> (sizeof(n) * 8 - shift_bits)));
}

__attribute__((no_sanitize("unsigned-shift-base")))
uint32_t circular_right_shift(uint32_t n, uint32_t shift_bits) {
	return ((n >> shift_bits) | (n << (sizeof(n) * 8 - shift_bits)));
}

__attribute__((no_sanitize("unsigned-shift-base")))
uint64_t circular_left_shift_bits(uint64_t n, uint32_t shift_bits, size_t num_bits) {
	// 0b00001110 <<@4 0 => 0b00001110;
	// 0b00001110 <<@4 1 => 0b00001101;
	// 0b00001110 <<@4 2 => 0b00001011;
	// 0b00001110 <<@4 3 => 0b00000111;
	return ((n << shift_bits) | (n >> (num_bits - shift_bits))) & ((1 << num_bits) - 1);
}

__attribute__((no_sanitize("unsigned-shift-base")))
uint64_t circular_right_shift_bits(uint64_t n, uint32_t shift_bits, size_t num_bits) {
	// 0b00001110 >>@4 0 => 0b00001110;
	// 0b00001110 >>@4 1 => 0b00000111;
	// 0b00001110 >>@4 2 => 0b00001011;
	// 0b00001110 >>@4 3 => 0b00001101;
	return ((n >> shift_bits) | (n << (num_bits - shift_bits))) & ((1 << num_bits) - 1);
}
