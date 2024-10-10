#pragma once

#include <stdbool.h>
#include <stdint.h>

bool composite_by_miller_rabin(uint64_t n, size_t rounds);
