#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#define PROG_NAME "ft_ssl"
#define ERR_PREFIX PROG_NAME ": Error"

#define lengthof(arr) (sizeof(arr) / sizeof(*arr))

size_t ft_strlen(char const *str);
ssize_t ft_putstr(int fd, char const *str);
// ssize_t ft_putendl(int fd, char *str);
int ft_strcmp(char const *s1, char const *s2);
bool ft_streq(char const *s1, char const *s2);
bool ft_str_starts_with(char const *haystack, char const *start);
void ft_memset(void *buf, uint8_t byte_value, size_t size);
bool ft_isprint(char c);
bool should_be_escaped(char c);
void print_escaped(int fd, char const *s, size_t len);
void ft_memcpy(void *dst, void const *src, size_t size);
void *__attribute((warn_unused_result)) ft_realloc(void *p, size_t old_size, size_t new_size);
char *__attribute((warn_unused_result)) ft_strdup(char const *str);
char *read_to_string(int fd, size_t *len);
uint32_t circular_left_shift(uint32_t n, uint32_t shift_bits);
uint32_t circular_right_shift(uint32_t n, uint32_t shift_bits);
uint64_t circular_left_shift_bits(uint64_t n, uint32_t shift_bits, size_t num_bits);
uint64_t circular_right_shift_bits(uint64_t n, uint32_t shift_bits, size_t num_bits);
