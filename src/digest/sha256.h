#pragma once

#include <stddef.h>

#include "error.h"
#include "hash.h"

struct hash256 sha256_buf(void *buf, size_t buf_size);
t_result sha256_fd(int fd, struct hash256 *hash256);
