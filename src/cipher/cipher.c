#include <assert.h>
#include <bsd/readpassphrase.h>
#include <fcntl.h>
#include <stdlib.h>

#include "cipher/base64.h"
#include "des.h"
#include "digest/md5.h"
#include "error.h"
#include "hash.h"
#include "random.h"
#include "utils.h"

enum enc_mode {
	MODE_ENCODE,
	MODE_DECODE,
};

enum block_cipher_mode {
	BC_ECB,
	BC_CBC,
};

struct base64_args {
	enum enc_mode mode;
	char *input_file;
	char *output_file;
};

struct des_args_raw {
	enum enc_mode mode;
	char *input_file;
	char *output_file;
	bool base64;
	char *key;
	char *pass;
	char *salt;
	char *init_vec;
};

struct des_args {
	enum enc_mode mode;
	char *input_file;
	char *output_file;
	bool base64;
	uint64_t key; // Stored in Big Endian
	uint64_t init_vec; // Stored in Big Endian
	uint64_t salt; // Stored in Big Endian
	bool print_salted;
	bool salt_given;
};

struct key_iv {
	uint8_t key[8];
	uint8_t iv[8];
};

#include <stdio.h>
struct key_iv bytes_to_key_iv(void const *bytes, size_t num_bytes, uint64_t salt) { // TODO: decide whether to use md5 or sha256
	struct key_iv key_iv;
	struct hash128 hash;

	size_t key_bytes = 0;
	size_t iv_bytes = 0;

	bool first = true;

	while (true) {
		struct md5_stream_data md5 = md5_init_stream();
		if (!first) {
			md5_stream(&md5, hash.bytes, sizeof(hash.bytes));
		} else {
			first = false;
		}
		md5_stream(&md5, bytes, num_bytes);
		md5_stream(&md5, &salt, sizeof(salt));
		hash = md5_stream_hash(&md5);


		// printf("\nhash: ");
		// for (uint8_t i = 0; i < sizeof(hash.bytes); i++) {
		// 	printf("%.2x", hash.bytes[i]);
		// }
		// printf("\n");

		size_t copied_bytes = 0;
		if (key_bytes < sizeof(key_iv.key)) {
			if (sizeof(key_iv.key) - key_bytes < sizeof(hash.bytes)) {
				copied_bytes = sizeof(key_iv.key) - key_bytes;
			}
			else {
				copied_bytes = sizeof(hash.bytes);
			}
			ft_memcpy(&key_iv.key[key_bytes], hash.bytes, copied_bytes);
			key_bytes += copied_bytes;
		}
		if (iv_bytes < sizeof(key_iv.iv) && key_bytes == sizeof(key_iv.key)) {
			size_t iv_copy_size = 0;
			if (sizeof(key_iv.iv) - iv_bytes < sizeof(hash.bytes)) {
				iv_copy_size = sizeof(key_iv.iv) - iv_bytes;
			}
			else {
				iv_copy_size = sizeof(hash.bytes);
			}
			ft_memcpy(&key_iv.iv[iv_bytes], &hash.bytes[copied_bytes], iv_copy_size);
			iv_bytes += iv_copy_size;
		}
		if (key_bytes == sizeof(key_iv.key) && iv_bytes == sizeof(key_iv.iv)) {
			return key_iv;
		}
	}
}

static t_result parse_base64_args(char **args, struct base64_args *opts) {
	*opts = (struct base64_args){
		.mode = MODE_ENCODE,
		.input_file = NULL,
		.output_file = NULL,
	};

	size_t index = 0;
	while (args[index] != NULL && args[index][0] == '-') {
		char *arg = args[index];
		if (ft_streq(&arg[1], "d")) {
			opts->mode = MODE_DECODE;
		}
		else if (ft_streq(&arg[1], "e")) {
			opts->mode = MODE_ENCODE;
		}
		else if (ft_streq(&arg[1], "i")) {
			index++;
			if (args[index] == NULL) {
				return set_error(E_OPT_MISSING_VALUE, "Option expected value, but it is missing");
			}
			opts->input_file = args[index];
		}
		else if (ft_streq(&arg[1], "o")) {
			index++;
			if (args[index] == NULL) {
				return set_error(E_OPT_MISSING_VALUE, "Option expected value, but it is missing");
			}
			opts->output_file = args[index];
		}
		else {
			return set_error(E_UNEXPECTED_OPT, "Unexpected option");
		}
		index++;
	}
	if (args[index] != NULL) {
		return set_error(E_UNEXPECTED_ARG, "Unexpected argument");
	}
	return OK;
}

static t_result get_des_args(char **args, struct des_args_raw *opts) {
	*opts = (struct des_args_raw){
		.mode = MODE_ENCODE,
		.input_file = NULL,
		.output_file = NULL,
		.base64 = false,
		.key = NULL,
		.pass = NULL,
		.salt = NULL,
		.init_vec = NULL,
	};

	size_t index = 0;
	while (args[index] != NULL && args[index][0] == '-') {
		char *arg = args[index];
		if (ft_streq(&arg[1], "a")) {
			opts->base64 = true;
		}
		else if (ft_streq(&arg[1], "d")) {
			opts->mode = MODE_DECODE;
		}
		else if (ft_streq(&arg[1], "e")) {
			opts->mode = MODE_ENCODE;
		}
		else if (ft_streq(&arg[1], "i")) {
			index++;
			if (args[index] == NULL) {
				return set_error(E_OPT_MISSING_VALUE, "Option expected value, but it is missing");
			}
			opts->input_file = args[index];
		}
		else if (ft_streq(&arg[1], "o")) {
			index++;
			if (args[index] == NULL) {
				return set_error(E_OPT_MISSING_VALUE, "Option expected value, but it is missing");
			}
			opts->output_file = args[index];
		}
		else if (ft_streq(&arg[1], "k")) {
			index++;
			if (args[index] == NULL) {
				return set_error(E_OPT_MISSING_VALUE, "Option expected value, but it is missing");
			}
			opts->key = args[index];
		}
		else if (ft_streq(&arg[1], "p")) {
			index++;
			if (args[index] == NULL) {
				return set_error(E_OPT_MISSING_VALUE, "Option expected value, but it is missing");
			}
			opts->pass = args[index];
		}
		else if (ft_streq(&arg[1], "s")) {
			index++;
			if (args[index] == NULL) {
				return set_error(E_OPT_MISSING_VALUE, "Option expected value, but it is missing");
			}
			opts->salt = args[index];
		}
		else if (ft_streq(&arg[1], "v")) {
			index++;
			if (args[index] == NULL) {
				return set_error(E_OPT_MISSING_VALUE, "Option expected value, but it is missing");
			}
			opts->init_vec = args[index];
		}
		else {
			return set_error(E_UNEXPECTED_OPT, "Unexpected option");
		}
		index++;
	}
	if (args[index] != NULL) {
		return set_error(E_UNEXPECTED_ARG, "Unexpected argument");
	}
	return OK;
}

static uint64_t parse_hex64(char const *str) {
	size_t len = ft_strlen(str);
	if (len < 16) {
		ft_putstr(STDERR_FILENO, "Warning: hex string is too short, padding with zero bytes to length\n");
	}
	size_t copy_len = len;
	if (len > 16) {
		copy_len = 16;
		ft_putstr(STDERR_FILENO, "Warning: hex string is too long, ignoring excess\n");
	}
	char s[] = "0000000000000000";
	ft_memcpy(s, str, copy_len);
	uint64_t hex = 0;
	size_t i = 0;
	while (s[i] != '\0') {
		hex *= 16;
		if ('0' <= s[i] && s[i] <= '9') {
			hex += s[i] - '0';
		}
		else if ('a' <= s[i] && s[i] <= 'f') {
			hex += s[i] - 'a' + 10;
		}
		else if ('A' <= s[i] && s[i] <= 'F') {
			hex += s[i] - 'A' + 10;
		}
		else {
			// FIXME: error
		}
		i++;
	}
	return hex;
}

//             | error | pw prompt | salted | key gen | salt gen | iv gen
// !p !k !s !v | false | true      | true   | true    | true     | true
// !p !k !s  v | false | true      | true   | true    | true     | false
// !p !k  s !v | false | true      | false  | true    | false    | true
// !p !k  s  v | false | true      | false  | true    | false    | false
// !p  k !s !v | CBC   | false     | false  | false   | true     | true
// !p  k !s  v | false | false     | false  | false   | true     | false
// !p  k  s !v | CBC   | false     | false  | false   | false    | true
// !p  k  s  v | false | false     | false  | false   | false    | false
//  p !k !s !v | false | false     | true   | true    | true     | true
//  p !k !s  v | false | false     | true   | true    | true     | false
//  p !k  s !v | false | false     | false  | true    | false    | true
//  p !k  s  v | false | false     | false  | true    | false    | false
//  p  k !s !v | false | false     | true   | false   | true     | true
//  p  k !s  v | false | false     | true   | false   | true     | false
//  p  k  s !v | false | false     | false  | false   | false    | true
//  p  k  s  v | false | false     | false  | false   | false    | false

static t_result get_salt(uint64_t *salt, struct des_args_raw const *opts_raw, uint8_t const salt_bytes[16]) {
	if (salt_bytes != NULL) {
		char const *magic = "Salted__";
		for (size_t i = 0; i < 8; i++) {
			if (salt_bytes[i] != magic[i]) {
				return set_error(E_BAD_DECRYPT, "Bad decrypt");
			}
		}
		ft_memcpy(salt, salt_bytes + 8, sizeof(salt));
	}
	else if (opts_raw->salt != NULL) {
		*salt = HOST_TO_BIG_ENDIAN(uint64_t, parse_hex64(opts_raw->salt));
	}
	else {
		*salt = ft_random_64();
	}
	return OK;
}

static t_result load_key_iv(struct key_iv *key_iv, uint64_t salt, struct des_args_raw const *opts_raw, enum block_cipher_mode mode) {
	if (opts_raw->pass != NULL) {
		*key_iv = bytes_to_key_iv(opts_raw->pass, ft_strlen(opts_raw->pass), salt);
	}
	else {
		if (opts_raw->key == NULL) {
			char buf[128];
			char verification_buf[128];
			if (readpassphrase("Enter passphrase:", buf, sizeof(buf), RPP_REQUIRE_TTY) == NULL) {
				return set_error(E_PASS_ERROR, "Error occured while getting the passphrase");
			}
			if (readpassphrase("Verify passphrase:", verification_buf, sizeof(verification_buf), RPP_REQUIRE_TTY) == NULL) {
				return set_error(E_PASS_ERROR, "Error occured while getting the passphrase");
			}
			if (!ft_streq(buf, verification_buf)) {
				return set_error(E_PASS_MISMATCH, "Passwords did not match");
			}
			*key_iv = bytes_to_key_iv(buf, ft_strlen(buf), salt);
			ft_memset(buf, 0, sizeof(buf));
			ft_memset(verification_buf, 0, sizeof(verification_buf));
		}
		else {
			switch (mode) {
				// DON'T REQUIRE IV
				case BC_ECB:
					break;
				// DO REQUIRE IV
				case BC_CBC: {
					if (opts_raw->init_vec == NULL) {
						return set_error(E_MISSING_OPT, "Expected one of -p or -v");
					}
					break;
				}
			}
		}
	}

	if (opts_raw->init_vec != NULL) {
		uint64_t iv = HOST_TO_BIG_ENDIAN(uint64_t, parse_hex64(opts_raw->init_vec));
		ft_memcpy(&key_iv->iv, &iv, sizeof(key_iv->iv));
	}

	if (opts_raw->key != NULL) {
		uint64_t key = HOST_TO_BIG_ENDIAN(uint64_t, parse_hex64(opts_raw->key));
		ft_memcpy(&key_iv->key, &key, sizeof(key_iv->key));
	}


	return OK;
}

t_result cmd_base64(char **args) {
	struct base64_args opts;
	if (parse_base64_args(args, &opts) != OK) {
		return FAIL;
	}
	int in_fd = STDIN_FILENO;
	if (opts.input_file != NULL) {
		in_fd = open(opts.input_file, O_RDONLY);
		if (in_fd < 0) {
			return set_error(E_ERRNO, opts.input_file);
		}
	}
	int out_fd = STDOUT_FILENO;
	if (opts.output_file != NULL) {
		out_fd = open(opts.output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644); // TODO: check permissions
		if (out_fd < 0) {
			if (in_fd != STDIN_FILENO) {
				close(in_fd);
			}
			return set_error(E_ERRNO, opts.output_file);
		}
	}
	switch (opts.mode) {
		case MODE_ENCODE: {
			char *s = base64_encode_fd(in_fd, 64, true);
			if (s == NULL) {
				if (in_fd != STDIN_FILENO) {
					close(in_fd);
				}
				if (out_fd != STDOUT_FILENO) {
					close(out_fd);
				}
				return FAIL;
			}
			size_t len = ft_strlen(s);
			write(out_fd, s, len);
			free(s);
			break;
		}
		case MODE_DECODE: { // FIXME: test this
			size_t len;
			char *s = (void*)base64_decode_fd(in_fd, &len);
			if (s == NULL) {
				if (in_fd != STDIN_FILENO) {
					close(in_fd);
				}
				if (out_fd != STDOUT_FILENO) {
					close(out_fd);
				}
				return FAIL;
			}
			write(out_fd, s, len);
			free(s);
			break;
		}
	}
	if (in_fd != STDIN_FILENO) {
		close(in_fd);
	}
	if (out_fd != STDOUT_FILENO) {
		close(out_fd);
	}
	return OK;
}

// static void des_encode_buf(const void *buf, size_t buf_size, uint8_t const key[8], uint8_t const iv[8], void *s, enum block_cipher_mode mode) {
// 	switch (mode) {
// 		case BC_ECB:
// 			return des_ecb_encode_buf(buf, buf_size, key, s);
// 		case BC_CBC:
// 			return des_cbc_encode_buf(buf, buf_size, key, iv, s);
// 	}
// }

static char *des_encode_fd(int fd, struct key_iv const *key_iv, size_t *size, enum block_cipher_mode mode) {
	switch (mode) {
		case BC_ECB:
			return des_ecb_encode_fd(fd, key_iv->key, size);
		case BC_CBC:
			return des_cbc_encode_fd(fd, key_iv->key, key_iv->iv, size);
	}
}

static t_result des_decode_buf(const void *buf, size_t buf_size, struct key_iv const *key_iv, void *s, size_t *size, enum block_cipher_mode mode) {
	switch (mode) {
		case BC_ECB:
			return des_ecb_decode_buf(buf, buf_size, key_iv->key, s, size);
		case BC_CBC:
			return des_cbc_decode_buf(buf, buf_size, key_iv->key, key_iv->iv, s, size);
	}
}

// static char *des_decode_fd(int fd, struct key_iv const *key_iv, size_t *size, enum block_cipher_mode mode) {
// 	switch (mode) {
// 		case BC_ECB:
// 			return des_ecb_decode_fd(fd, key_iv->key, size);
// 		case BC_CBC:
// 			return des_cbc_decode_fd(fd, key_iv->key, key_iv->iv, size);
// 	}
// }

static t_result run_des(char **args, enum block_cipher_mode mode) {
	struct des_args_raw opts;
	if (get_des_args(args, &opts) != OK) {
		return FAIL;
	}

	int in_fd = -1;
	int out_fd = -1;
	char *s = NULL;
	char *b64 = NULL;
	uint8_t *buf = NULL;

	in_fd = STDIN_FILENO;
	if (opts.input_file != NULL) {
		in_fd = open(opts.input_file, O_RDONLY);
		if (in_fd < 0) {
			(void)set_error(E_ERRNO, opts.input_file);
			goto error;
		}
	}
	out_fd = STDOUT_FILENO;
	if (opts.output_file != NULL) {
		out_fd = open(opts.output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644); // TODO: check permissions
		if (out_fd < 0) {
			(void)set_error(E_ERRNO, opts.output_file);
			goto error;
		}
	}

	struct key_iv key_iv;
	uint64_t salt;
	switch (opts.mode) {
		case MODE_ENCODE: {
			if (get_salt(&salt, &opts, NULL) != OK) {
				goto error;
			}
			if (load_key_iv(&key_iv, salt, &opts, mode) != OK) {
				goto error;
			}
			size_t size;
			s = des_encode_fd(in_fd, &key_iv, &size, mode);
			if (s == NULL) {
				goto error;
			}
			if (opts.salt == NULL && (opts.pass != NULL || opts.key == NULL)) {
				char* salted = malloc(16 + size);
				if (salted == NULL) {
					(void)set_error(E_ERRNO, NULL);
					goto error;
				}
				ft_memcpy(salted, "Salted__", 8);
				ft_memcpy(salted + 8, &salt, sizeof(salt));
				ft_memcpy(salted + 16, s, size);
				size += 16;
				free(s);
				s = salted;
			}
			if (opts.base64) {
				b64 = base64_encode_buf((uint8_t *)s, size, 64, true);
				if (b64 == NULL) {
					goto error;
				}
				ft_putstr(out_fd, b64);
				free(b64);
				b64 = NULL;
			}
			else {
				write(out_fd, s, size);
			}
			free(s);
			s = NULL;
			break;
		}
		case MODE_DECODE: {
			size_t size = 0;
			size_t input_size = 0;
			if (opts.base64) {
				buf = base64_decode_fd(in_fd, &input_size);
				if (buf == NULL) {
					goto error;
				}
			}
			else {
				buf = (uint8_t*)read_to_string(in_fd, &input_size);
				if (buf == NULL) {
					goto error;
				}
			}
			uint8_t *real_buf = buf;
			uint8_t *salt_str = NULL;
			if (opts.salt == NULL) {
				if (input_size < 16) {
					(void)set_error(E_BAD_DECRYPT, "Bad decrypt");
					goto error;
				}
				salt_str = buf;
				real_buf = buf + 16;
				input_size -= 16;
			}
			if (get_salt(&salt, &opts, salt_str) != OK) {
				goto error;
			}
			if (load_key_iv(&key_iv, salt, &opts, mode) != OK) {
				goto error;
			}
			s = malloc(input_size);
			if (s == NULL) {
				(void)set_error(E_ERRNO, NULL);
				goto error;
			}
			if (des_decode_buf(real_buf, input_size, &key_iv, s, &size, mode) != OK) {
				goto error;
			}
			free(buf);
			buf = NULL;
			write(out_fd, s, size);
			free(s);
			s = NULL;
			break;
		}
	}
	t_result result = OK;
	goto clean;

	error: result = FAIL;
	clean: {
		if (opts.input_file != NULL && in_fd >= 0) {
			close(in_fd);
		}
		if (opts.output_file != NULL && out_fd >= 0) {
			close(out_fd);
		}
		free(s);
		free(b64);
		free(buf);
		return result;
	}
}

t_result cmd_des_ecb(char **args) {
	return run_des(args, BC_ECB);
}

t_result cmd_des_cbc(char **args) {
	return run_des(args, BC_CBC);
}

t_result cmd_des(char **args) {
	return cmd_des_cbc(args);
}
