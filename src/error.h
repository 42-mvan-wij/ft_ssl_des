#pragma once

#define MAX_ERR_MSG_SIZE 512

typedef enum result {
	OK = 0,
	FAIL,
} __attribute__((warn_unused_result)) t_result;

enum ft_error {
	E_NONE,
	E_ERRNO,
	E_INVALID_CMD,
	E_OPT_MISSING_VALUE,
	E_UNEXPECTED_OPT,
	E_UNEXPECTED_ARG,
	E_INVALID_PASS_ARG,
	E_INVALID_LENGTH,
	E_MISSING_OPT,
	E_PASS_ERROR,
	E_PASS_MISMATCH,
	E_B64_EXPECTED_END,
	E_B64_INVALID_LEN,
	E_B64_INVALID_CHAR,
	E_DES_BAD_BLOCK,
	E_BAD_DECRYPT,
};

t_result set_error(enum ft_error errnum, char const *msg);
void * __attribute__((warn_unused_result)) set_error_null(enum ft_error errnum, char const *msg);
void * __attribute__((warn_unused_result)) retain_error_null(char const *msg);
void clear_error(void);
void append_error_msg(char const *msg_append);
enum ft_error get_error(void);
char const *get_error_msg(void);
void print_error(int fd, char const *prefix);

