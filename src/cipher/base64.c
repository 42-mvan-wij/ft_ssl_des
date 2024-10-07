#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "error.h"
#include "utils.h"

// size_t base64_decode_len(size_t len_exclude_pad) {
// 	size_t full24 = len_exclude_pad / 4;
// 	size_t extra_sextets = len_exclude_pad % 4;
// 	assert(extra_sextets != 1);
//
// 	size_t extra_octets = (extra_sextets * 6) / 8;
//
// 	return full24 * 3 + extra_octets;
// }
//
// size_t base64_decode_len_str(char *base64) {
// 	size_t len = ft_strlen(base64);
// 	while (base64[len - 1] == '=') {
// 		len--;
// 	}
// 	return base64_decode_len(len);
// }
//
// size_t count_base64_bits(char *base64) { // FIXME: remove
// 	size_t len = ft_strlen(base64);
// 	while (base64[len - 1] == '=') {
// 		len--;
// 	}
// 	size_t padding = (4 - (len % 4)) % 4;
// 	return len * 6 - 2 * padding;
// }

size_t base64_encode_len(size_t num_bits, bool include_padding) {
	if (include_padding) {
		return ((num_bits + 23) / 24) * 4; // TODO: check if correct
	}
	else {
		return (num_bits + 5) / 6;
	}
}

size_t base64_decode_len_octets(size_t encoded_len, size_t padding_len) {
	return ((encoded_len - padding_len) * 6) / 8;
}

static char encode_base64_char(uint8_t sextet) {
	static char const base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	assert(sextet < lengthof(base64));
	return base64[sextet];
}

static uint8_t decode_base64_char(char b64_char) {
	static uint8_t const base64[] = {
		['A'] = 0,
		['B'] = 1,
		['C'] = 2,
		['D'] = 3,
		['E'] = 4,
		['F'] = 5,
		['G'] = 6,
		['H'] = 7,
		['I'] = 8,
		['J'] = 9,
		['K'] = 10,
		['L'] = 11,
		['M'] = 12,
		['N'] = 13,
		['O'] = 14,
		['P'] = 15,
		['Q'] = 16,
		['R'] = 17,
		['S'] = 18,
		['T'] = 19,
		['U'] = 20,
		['V'] = 21,
		['W'] = 22,
		['X'] = 23,
		['Y'] = 24,
		['Z'] = 25,

		['a'] = 26,
		['b'] = 27,
		['c'] = 28,
		['d'] = 29,
		['e'] = 30,
		['f'] = 31,
		['g'] = 32,
		['h'] = 33,
		['i'] = 34,
		['j'] = 35,
		['k'] = 36,
		['l'] = 37,
		['m'] = 38,
		['n'] = 39,
		['o'] = 40,
		['p'] = 41,
		['q'] = 42,
		['r'] = 43,
		['s'] = 44,
		['t'] = 45,
		['u'] = 46,
		['v'] = 47,
		['w'] = 48,
		['x'] = 49,
		['y'] = 50,
		['z'] = 51,

		['0'] = 52,
		['1'] = 53,
		['2'] = 54,
		['3'] = 55,
		['4'] = 56,
		['5'] = 57,
		['6'] = 58,
		['7'] = 59,
		['8'] = 60,
		['9'] = 61,

		['+'] = 62,
		['/'] = 63,
	};

	assert(b64_char == 'A' || ((size_t)b64_char < lengthof(base64) && base64[(int)b64_char] != 0));
	return base64[(int)b64_char];
}

static bool is_base64_char(char b64_char) {
	return
		('A' <= b64_char && b64_char <= 'Z') ||
		('a' <= b64_char && b64_char <= 'z') ||
		('0' <= b64_char && b64_char <= '9') ||
		b64_char == '+' ||
		b64_char == '/';
}










struct base64_encode_stream {
	char *b64;
	size_t b64_len;
	size_t b64_size;
	size_t max_width;
	uint16_t bits;
	uint8_t bit_num;
	bool ending_break;
};

void free_base64_encode_stream(struct base64_encode_stream *stream) {
	free(stream->b64);
	stream->b64 = NULL;
}

t_result base64_encode_stream(struct base64_encode_stream *stream, size_t max_width, bool ending_break) {
	*stream = (struct base64_encode_stream){
		.b64 = malloc(64),
		.b64_len = 0,
		.b64_size = 64,
		.max_width = max_width,
		.bits = 0,
		.bit_num = 0,
		.ending_break = ending_break,
	};
	if (stream->b64 == NULL) {
		return set_error(E_ERRNO, NULL);
	}
	return OK;
}

t_result base64_encode_data(struct base64_encode_stream *stream, uint8_t const *data, size_t bytes) {
	while (bytes > 0) {
		bytes--;
		stream->bits |= (*data) << (12 - stream->bit_num - 8);
		stream->bit_num += 8;
		while (stream->bit_num >= 6) {
			bool add_newline = stream->max_width != 0 && (stream->b64_len + 1) % (stream->max_width + 1) == 0;
			if (stream->b64_len + add_newline >= stream->b64_size) {
				// NOTE: assume that b64_size starts at at least 2
				stream->b64 = ft_realloc(stream->b64, stream->b64_size, stream->b64_size * 2);
				if (stream->b64 == NULL) {
					free_base64_encode_stream(stream);
					return set_error(E_ERRNO, NULL);
				}
				stream->b64_size *= 2;
			}
			if (add_newline) {
				stream->b64[stream->b64_len] = '\n';
				stream->b64_len += 1;
			}
			uint8_t sextet = (stream->bits >> 6) & 0b111111;
			stream->b64[stream->b64_len] = encode_base64_char(sextet);
			stream->b64_len += 1;
			stream->bits = (stream->bits & 0x3FF) << 6;
			// stream->bits <<= 6;
			stream->bit_num -= 6;
		}
		data++;
	}
	return OK;
}

char *base64_encode_final(struct base64_encode_stream *stream) {
	uint8_t add_newline = stream->ending_break ? 1 : 0;
	size_t breakless_len = stream->b64_len;
	if (stream->max_width != 0) {
		breakless_len = stream->b64_len - stream->b64_len / (stream->max_width + 1);
	}
	if (stream->bit_num == 0 && breakless_len % 4 == 0) {
		if (stream->b64_len + add_newline >= stream->b64_size) {
			stream->b64 = ft_realloc(stream->b64, stream->b64_size, stream->b64_size + 1 + add_newline);
			if (stream->b64 == NULL) {
				free_base64_encode_stream(stream);
				return set_error_null(E_ERRNO, NULL);
			}
			stream->b64_size = stream->b64_size + 1 + add_newline;
		}
		if (stream->ending_break) {
			stream->b64[stream->b64_len] = '\n';
			stream->b64_len += 1;
		}
		stream->b64[stream->b64_len] = '\0';
		return stream->b64;
	}
	uint8_t add_chars = 4 - (breakless_len % 4);
	size_t new_breakless_len = breakless_len + add_chars;
	size_t new_breaks = 0;
	if (stream->max_width != 0) {
		new_breaks = stream->b64_len / stream->max_width;
	}
	size_t new_len = new_breakless_len + new_breaks;
	if (new_len + add_newline + 1 >= stream->b64_size) {
		stream->b64 = ft_realloc(stream->b64, stream->b64_size, new_len + add_newline + 1);
		if (stream->b64 == NULL) {
			free_base64_encode_stream(stream);
			return set_error_null(E_ERRNO, NULL);
		}
		stream->b64_size = new_len + add_newline + 1;
	}
	uint8_t padding = add_chars;
	if (stream->bit_num > 0) {
		if (stream->max_width != 0 && (stream->b64_len + 1) % (stream->max_width + 1) == 0) {
			stream->b64[stream->b64_len] = '\n';
			stream->b64_len += 1;
		}
		uint8_t sextet = (stream->bits >> 6) & 0b00111111;
		stream->b64[stream->b64_len] = encode_base64_char(sextet);
		stream->b64_len += 1;
		padding -= 1;
	}
	while (padding > 0) {
		if (stream->max_width != 0 && (stream->b64_len + 1) % (stream->max_width + 1) == 0) {
			stream->b64[stream->b64_len] = '\n';
			stream->b64_len += 1;
		}
		stream->b64[stream->b64_len] = '=';
		stream->b64_len += 1;
		padding--;
	}
	if (stream->ending_break) {
		stream->b64[stream->b64_len] = '\n';
		stream->b64_len += 1;
	}
	stream->b64[stream->b64_len] = '\0';
	return stream->b64;
}




struct base64_decode_stream {
	uint8_t *bytes;
	size_t bytes_len;
	size_t bytes_size;
	uint16_t bits;
	uint8_t bit_num;
	bool should_finish;
};

void free_base64_decode_stream(struct base64_decode_stream *stream) {
	free(stream->bytes);
	stream->bytes = NULL;
}

t_result base64_decode_stream(struct base64_decode_stream *stream) {
	*stream = (struct base64_decode_stream){
		.bytes = malloc(64),
		.bytes_len = 0,
		.bytes_size = 64,
		.bits = 0,
		.bit_num = 0,
	};
	if (stream->bytes == NULL) {
		return set_error(E_ERRNO, NULL);
	}
	return OK;
}

t_result base64_decode_data(struct base64_decode_stream *stream, char const *b64_data, size_t size) {
	while (size > 0) {
		size--;
		if (*b64_data == ' ' || *b64_data == '\n') {
			b64_data++;
			continue;
		}
		if (*b64_data == '=') {
			b64_data++;
			stream->should_finish = true;
			continue;
		}
		else if (stream->should_finish) {
			free_base64_decode_stream(stream);
			return set_error(E_B64_EXPECTED_END, "Unexpectedly got data after padding");
		}

		char b64_char = *b64_data;
		if (!is_base64_char(b64_char)) {
			return set_error(E_B64_INVALID_CHAR, "Invalid base64 character");
		}

		stream->bits |= decode_base64_char(b64_char) << (12 - stream->bit_num - 6);
		stream->bit_num += 6;
		while (stream->bit_num >= 8) {
			if (stream->bytes_len == stream->bytes_size) {
				stream->bytes = ft_realloc(stream->bytes, stream->bytes_size, stream->bytes_size * 2);
				if (stream->bytes == NULL) {
					free_base64_decode_stream(stream);
					return set_error(E_ERRNO, NULL);
				}
				stream->bytes_size *= 2;
			}
			uint8_t octet = (stream->bits >> 4) & 0xFF;
			stream->bytes[stream->bytes_len] = octet;
			stream->bytes_len += 1;
			stream->bits = (stream->bits & 0xFF) << 8;
			stream->bit_num -= 8;
		}
		b64_data++;
	}
	return OK;
}

uint8_t *base64_decode_final(struct base64_decode_stream *stream, size_t *out_size) {
	assert(stream->bit_num % 2 == 0);

	if (stream->bit_num == 6) {
		// NOTE: a bit_num of 6 would mean a sextet length of 1 (mod 4), which is invalid when encoding octets
		return set_error_null(E_B64_INVALID_LEN, "Invalid decode length");
	}

	*out_size = stream->bytes_len;
	return stream->bytes;
}



char *base64_encode_buf(uint8_t const *data, size_t bytes, size_t max_width, bool ending_break) {
	struct base64_encode_stream stream;
	if (base64_encode_stream(&stream, max_width, ending_break) != OK) {
		free_base64_encode_stream(&stream);
		return retain_error_null(NULL);
	}
	if (base64_encode_data(&stream, data, bytes) != OK) {
		free_base64_encode_stream(&stream);
		return retain_error_null(NULL);
	}
	char *b64 = base64_encode_final(&stream);
	if (b64 == NULL) {
		free_base64_encode_stream(&stream);
		return retain_error_null(NULL);
	}
	return b64;
}

char *base64_encode_fd(int fd, size_t max_width, bool ending_break) {
	struct base64_encode_stream stream;

	if (base64_encode_stream(&stream, max_width, ending_break) != OK) {
		return retain_error_null(NULL);
	}

	uint8_t buf[128];
	while (true) {
		ssize_t nread = read(fd, buf, sizeof(buf));
		if (nread < 0) {
			free_base64_encode_stream(&stream);
			return set_error_null(E_ERRNO, NULL);
		}
		if (nread == 0) {
			char *b64 = base64_encode_final(&stream);
			if (b64 == NULL) {
				free_base64_encode_stream(&stream);
				return retain_error_null(NULL);
			}
			return b64;
		}
		if (base64_encode_data(&stream, buf, nread) != OK) {
			free_base64_encode_stream(&stream);
			return retain_error_null(NULL);
		}
	}
}

uint8_t *base64_decode_buf(char const *b64_str, size_t size, size_t *out_size) {
	struct base64_decode_stream stream;
	if (base64_decode_stream(&stream) != OK) {
		return retain_error_null(NULL);
	}
	if (base64_decode_data(&stream, b64_str, size) != OK) {
		return retain_error_null(NULL);
	}
	uint8_t *bytes = base64_decode_final(&stream, out_size);
	if (bytes == NULL) {
		free_base64_decode_stream(&stream);
		return retain_error_null(NULL);
	}
	return bytes;
}

uint8_t *base64_decode_fd(int fd, size_t *out_size) {
	struct base64_decode_stream stream;

	if (base64_decode_stream(&stream) != OK) {
		return retain_error_null(NULL);
	}

	char buf[128];
	while (true) {
		ssize_t nread = read(fd, buf, sizeof(buf));
		if (nread < 0) {
			free_base64_decode_stream(&stream);
			return set_error_null(E_ERRNO, NULL);
		}
		if (nread == 0) {
			uint8_t *bytes = base64_decode_final(&stream, out_size);
			if (bytes == NULL) {
				free_base64_decode_stream(&stream);
				return retain_error_null(NULL);
			}
			return bytes;
		}
		if (base64_decode_data(&stream, buf, nread) != OK) {
			free_base64_decode_stream(&stream);
			return retain_error_null(NULL);
		}
	}
}
