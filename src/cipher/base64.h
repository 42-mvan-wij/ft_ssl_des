#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "error.h"

// void base64_decode_buf(uint8_t const *buf, size_t buf_size, char *out_buf);
// uint8_t *base64_decode_fd(int fd, size_t *num_octets);
// void base64_encode_buf(uint8_t const *buf, size_t buf_size, char *out_buf);
// char *base64_encode_fd(int fd);
size_t base64_encode_len(size_t num_bits, bool include_padding); // TODO: do I even need these two
size_t base64_decode_len_octets(size_t encoded_len, size_t padding_len);

char *base64_encode_buf(uint8_t const *data, size_t bytes, size_t max_width, bool ending_break);
char *base64_encode_fd(int fd, size_t max_width, bool ending_break);
uint8_t *base64_decode_buf(char const *b64_str, size_t size, size_t *out_size);
uint8_t *base64_decode_fd(int fd, size_t *out_size);



struct base64_encode_stream {
	char *b64;
	size_t b64_len;
	size_t b64_size;
	size_t max_width;
	uint16_t bits;
	uint8_t bit_num;
	bool ending_break;
};
struct base64_decode_stream {
	uint8_t *bytes;
	size_t bytes_len;
	size_t bytes_size;
	uint16_t bits;
	uint8_t bit_num;
	bool should_finish;
};

void free_base64_encode_stream(struct base64_encode_stream *stream);
t_result base64_encode_stream(struct base64_encode_stream *stream, size_t max_width, bool ending_break);
t_result base64_encode_data(struct base64_encode_stream *stream, uint8_t const *data, size_t bytes);
char *base64_encode_final(struct base64_encode_stream *stream);

void free_base64_decode_stream(struct base64_decode_stream *stream);
t_result base64_decode_stream(struct base64_decode_stream *stream);
t_result base64_decode_data(struct base64_decode_stream *stream, char const *b64_data, size_t size);
uint8_t *base64_decode_final(struct base64_decode_stream *stream, size_t *out_size);
