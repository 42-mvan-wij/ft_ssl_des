#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

/*
 * If `size_bytes` is above 256 this may not work as expected, see `man 4 random` aka `man urandom`
 */
ssize_t ft_random(void *buf, size_t size_bytes) {
	int fd_random = open("/dev/urandom", O_RDONLY); // TODO: only use 1 instance
	ssize_t r = read(fd_random, buf, size_bytes);
	close(fd_random);
	return r;
}

uint64_t ft_random_64() {
	uint64_t r;
	ft_random(&r, sizeof(r));
	return r;
}

uint64_t rand_in_range_inclusive(uint64_t low, uint64_t high) {
	return (ft_random_64() % (high - low + 1)) + low;
}

