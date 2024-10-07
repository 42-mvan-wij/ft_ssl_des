#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "cipher.h"
#include "digest.h"
#include "utils.h"

#define PROG_NAME "ft_ssl"


// #include <stdio.h>
// void print_buf(uint8_t *buf_bytes, size_t size) {
// 	for (size_t ii = 0; ii < size; ii++) {
// 		for (size_t jj = 0; jj < 8; jj++) {
// 			printf("%c", (buf_bytes[ii] >> (8 - jj - 1)) & 1 ? '1' : '0');
// 		}
// 		printf(" ");
// 		if (ii % 8 == 7) {
// 			printf("\n");
// 		}
// 		// printf("%.2x ", buf_bytes[ii]);
// 	}
// 	printf("\n");
//
// }



#include <stdio.h>
#include "base64.h"
// #include <limits.h>
// #include <ctype.h>
// #include "sha256.h"
// #include "hash.h"
t_result cmd_test(char **args) {
	(void)args;
	char *b64 = base64_encode_buf((void*)"aaa\n", 4);
	printf("b64: <%s>\n", b64);
	free(b64);
	return OK;
}

static t_result run_cmd(char *cmd, char **args) {
	static struct {
		char *cmd_name;
		t_result(*cmd_fn)(char **args);
	} dispatch_table[] = {
		{ "md5", &cmd_md5 },
		{ "sha256", &cmd_sha256 },

		{ "base64", &cmd_base64 },
		{ "des", &cmd_des },
		{ "des-ecb", &cmd_des_ecb },
		{ "des-cbc", &cmd_des_cbc },

		{ "test", &cmd_test },
	};

	for (size_t i = 0; i < sizeof(dispatch_table) / sizeof(*dispatch_table); i++) {
		if (ft_streq(cmd, dispatch_table[i].cmd_name)) {
			if (dispatch_table[i].cmd_fn(args) != OK) {
				return FAIL;
			}
			return OK;
		}
	}
	(void)set_error(E_INVALID_CMD, "'");
	append_error_msg(cmd);
	append_error_msg("' is an invalid command.");
	return FAIL;
}

void list_commands() {
	ft_putstr(STDERR_FILENO, 
		"Standard Commands:\n"
		"\n"
		"Message Digest Commands:\n"
		"md5\n"
		"sha256\n"
		"\n"
		"Cipher Commands:\n"
		"base64\n"
		"des\n"
		"des-ecb\n"
		"des-cbc\n"
	);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		ft_putstr(STDERR_FILENO, "usage: " PROG_NAME " command [flag] [file/string]\n");
		return EXIT_FAILURE;
	}
	if (run_cmd(argv[1], &argv[2]) != OK) {
		print_error(STDERR_FILENO, ERR_PREFIX);
		if (get_error() == E_INVALID_CMD) {
			list_commands();
		}
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
