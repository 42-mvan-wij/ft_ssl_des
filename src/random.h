#include <unistd.h>
#include <stdint.h>

ssize_t ft_random(void *buf, size_t size_bytes);
uint64_t ft_random_64();
uint32_t ft_random_32();
uint64_t rand_in_range_inclusive(uint64_t low, uint64_t high);

