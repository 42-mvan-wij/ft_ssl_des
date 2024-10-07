#pragma once

#include <stddef.h>

#include "error.h"
#include "hash.h"

struct md5 {
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
};

struct md5_stream_data {
	uint8_t buf[64];
	struct md5 state;
	size_t msg_len;
	uint8_t buf_len;
};

struct hash128 md5_buf(void *buf, size_t buf_size);
t_result md5_fd(int fd, struct hash128 *hash128);
struct md5_stream_data md5_init_stream(void);
void md5_stream(struct md5_stream_data *stream_data, void const *buf, size_t buf_size);
struct hash128 md5_stream_hash(struct md5_stream_data *stream_data);
