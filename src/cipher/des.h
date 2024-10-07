#pragma once

#include <stddef.h>
#include <stdint.h>

#include "error.h"

void des_ecb_encode_buf(void const *buf, size_t buf_size, uint8_t const key[8], void *out_buf);
char *des_ecb_encode_fd(int fd, uint8_t const key[8], size_t *size);
t_result des_ecb_decode_buf(void const *buf, size_t buf_size, uint8_t const key[8], void *out_buf, size_t *real_length);
char *des_ecb_decode_fd(int fd, uint8_t const key[8], size_t *size);

void des_cbc_encode_buf(void const *buf, size_t buf_size, uint8_t const key[8], uint8_t const iv[8], void *out_buf);
char *des_cbc_encode_fd(int fd, uint8_t const key[8], uint8_t const iv[8], size_t *size);
t_result des_cbc_decode_buf(void const *buf, size_t buf_size, uint8_t const key[8], uint8_t const iv[8], void *out_buf, size_t *real_length);
char *des_cbc_decode_fd(int fd, uint8_t const key[8], uint8_t const iv[8], size_t *size);
