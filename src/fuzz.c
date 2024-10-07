#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include "cipher.h"
#include "digest.h"

// Source: https://github.com/google/security-research-pocs/blob/d10780c3ddb8070dff6c5e5862c93c01392d1727/autofuzz/fuzz_utils.cc#L31
int delete_file(const char *pathname) {
	int ret = unlink(pathname);
	if (ret == -1) {
		warn("failed to delete \"%s\"", pathname);
	}

	free((void *)pathname);

	return ret;
}

// Source: https://github.com/google/security-research-pocs/blob/d10780c3ddb8070dff6c5e5862c93c01392d1727/autofuzz/fuzz_utils.cc#L42
char *buf_to_file(const uint8_t *buf, size_t size) {
	char *pathname = strdup("/dev/shm/fuzz-XXXXXX");
	if (pathname == NULL) {
		return NULL;
	}

	int fd = mkstemp(pathname);
	if (fd == -1) {
		warn("mkstemp(\"%s\")", pathname);
		free(pathname);
		return NULL;
	}

	size_t pos = 0;
	while (pos < size) {
		int nbytes = write(fd, &buf[pos], size - pos);
		if (nbytes <= 0) {
		if (nbytes == -1 && errno == EINTR) {
			continue;
		}
		warn("write");
		goto err;
		}
		pos += nbytes;
	}

	if (close(fd) == -1) {
		warn("close");
		goto err;
	}

	return pathname;

err:
	delete_file(pathname);
	return NULL;
}

///////////////////////////////////////////////////

char *take_string(uint8_t const *data, size_t size, size_t string_max_len, uint8_t *len, size_t *bytes_taken) {
	uint8_t string_len = (*data) % string_max_len;
	if (size < string_len + 1) {
		return NULL;
	}
	char *string = malloc(string_len + 1);
	if (string == NULL) {
		exit(EXIT_FAILURE);
	}
	memcpy(string, data + 1, string_len);
	string[string_len] = '\0';
	*len = string_len;
	*bytes_taken += string_len + 1;
	return string;
}

int take_u64(uint8_t const *data, size_t size, uint64_t *n, size_t *bytes_taken) {
	if (size < sizeof(*n)) {
		return -1;
	}
	memcpy(n, data, sizeof(*n));
	*bytes_taken += sizeof(*n);
	return 0;
}

void u64_to_hex(uint64_t n, char hex[17]) {
	memcpy(hex, "0000000000000000", 17);
	for (uint8_t i = 0; i < 16; i++) {
		uint8_t digit = n % 16;
		n /= 16;
		if (digit <= 9) {
			hex[16 - i - 1] = digit + '0';
		}
		else {
			hex[16 - i - 1] = digit - 10 + 'a';
		}
	}
}

///////////////////////////////////////////////////

int fuzz_md5(uint8_t const *data, size_t size) {
	char *file_path = buf_to_file(data, size);
	if (file_path == NULL) {
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-q", file_path, NULL};
	(void)cmd_md5(args);

	delete_file(file_path);
	return 0;
}

int fuzz_sha256(uint8_t const *data, size_t size) {
	char *file_path = buf_to_file(data, size);
	if (file_path == NULL) {
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-q", file_path, NULL};
	(void)cmd_md5(args);

	delete_file(file_path);
	return 0;
}

int fuzz_base64_encode(uint8_t const *data, size_t size) {
	char *file_path = buf_to_file(data, size);
	if (file_path == NULL) {
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-e", "-i", file_path, "-o", "/dev/null", NULL};
	(void)cmd_base64(args);

	delete_file(file_path);
	return 0;
}

int fuzz_base64_decode(uint8_t const *data, size_t size) {
	char *file_path = buf_to_file(data, size);
	if (file_path == NULL) {
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-d", "-i", file_path, "-o", "/dev/null", NULL};
	(void)cmd_base64(args);

	delete_file(file_path);
	return 0;
}

int fuzz_des_ecb_encode_pass(uint8_t const *data, size_t size) {
	size_t bytes_taken = 0;

	uint8_t pass_len;
	char *pass = take_string(data + bytes_taken, size - bytes_taken, 16, &pass_len, &bytes_taken);
	if (pass == NULL) {
		return 0;
	}

	char *file_path = buf_to_file(data + bytes_taken, size - bytes_taken);
	if (file_path == NULL) {
		free(pass);
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-e", "-i", file_path, "-o", "/dev/null", "-p", pass, NULL};
	(void)cmd_des_ecb(args);

	free(pass);
	delete_file(file_path);
	return 0;
}

int fuzz_des_ecb_encode_key(uint8_t const *data, size_t size) {
	size_t bytes_taken = 0;

	uint64_t key;
	if (take_u64(data + bytes_taken, size - bytes_taken, &key, &bytes_taken) != 0) {
		return 0;
	}
	char key_string[17];
	u64_to_hex(key, key_string);

	char *file_path = buf_to_file(data + bytes_taken, size - bytes_taken);
	if (file_path == NULL) {
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-e", "-i", file_path, "-o", "/dev/null", "-k", key_string, NULL};
	(void)cmd_des_ecb(args);

	delete_file(file_path);
	return 0;
}

int fuzz_des_ecb_decode_key(uint8_t const *data, size_t size) {
	size_t bytes_taken = 0;

	uint64_t key;
	if (take_u64(data + bytes_taken, size - bytes_taken, &key, &bytes_taken) != 0) {
		return 0;
	}
	char key_string[17];
	u64_to_hex(key, key_string);

	char *file_path = buf_to_file(data + bytes_taken, size - bytes_taken);
	if (file_path == NULL) {
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-d", "-i", file_path, "-o", "/dev/null", "-k", key_string, NULL};
	(void)cmd_des_ecb(args);

	delete_file(file_path);
	return 0;
}

int fuzz_des_ecb_decode_pass(uint8_t const *data, size_t size) {
	size_t bytes_taken = 0;

	uint8_t pass_len;
	char *pass = take_string(data + bytes_taken, size - bytes_taken, 16, &pass_len, &bytes_taken);
	if (pass == NULL) {
		return 0;
	}

	char *file_path = buf_to_file(data + bytes_taken, size - bytes_taken);
	if (file_path == NULL) {
		free(pass);
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-d", "-i", file_path, "-o", "/dev/null", "-p", pass, NULL};
	(void)cmd_des_ecb(args);

	free(pass);
	delete_file(file_path);
	return 0;
}

int fuzz_des_ecb_decode_pass_salt(uint8_t const *data, size_t size) {
	size_t bytes_taken = 0;

	uint8_t pass_len;
	char *pass = take_string(data + bytes_taken, size - bytes_taken, 16, &pass_len, &bytes_taken);
	if (pass == NULL) {
		return 0;
	}
	uint64_t salt;
	char salt_string[17];
	if (take_u64(data + bytes_taken, size - bytes_taken, &salt, &bytes_taken) == 0) {
		free(pass);
		return 0;
	}
	u64_to_hex(salt, salt_string);

	char *file_path = buf_to_file(data + bytes_taken, size - bytes_taken);
	if (file_path == NULL) {
		free(pass);
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-d", "-i", file_path, "-o", "/dev/null", "-p", pass, "-s", salt_string, NULL};
	(void)cmd_des_ecb(args);

	free(pass);
	delete_file(file_path);
	return 0;
}

int fuzz_des_cbc_encode_pass(uint8_t const *data, size_t size) {
	size_t bytes_taken = 0;

	uint8_t pass_len;
	char *pass = take_string(data + bytes_taken, size - bytes_taken, 16, &pass_len, &bytes_taken);
	if (pass == NULL) {
		return 0;
	}

	char *file_path = buf_to_file(data + bytes_taken, size - bytes_taken);
	if (file_path == NULL) {
		free(pass);
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-e", "-i", file_path, "-o", "/dev/null", "-p", pass, NULL};
	(void)cmd_des_cbc(args);

	free(pass);
	delete_file(file_path);
	return 0;
}

int fuzz_des_cbc_encode_key_iv(uint8_t const *data, size_t size) {
	size_t bytes_taken = 0;

	uint64_t key;
	if (take_u64(data + bytes_taken, size - bytes_taken, &key, &bytes_taken) != 0) {
		return 0;
	}
	char key_string[17];
	u64_to_hex(key, key_string);

	uint64_t iv;
	if (take_u64(data + bytes_taken, size - bytes_taken, &iv, &bytes_taken) != 0) {
		return 0;
	}
	char iv_string[17];
	u64_to_hex(iv, iv_string);

	char *file_path = buf_to_file(data + bytes_taken, size - bytes_taken);
	if (file_path == NULL) {
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-e", "-i", file_path, "-o", "/dev/null", "-k", key_string, "-v", iv_string, NULL};
	(void)cmd_des_cbc(args);

	delete_file(file_path);
	return 0;
}

int fuzz_des_cbc_decode_key_iv(uint8_t const *data, size_t size) {
	size_t bytes_taken = 0;

	uint64_t key;
	if (take_u64(data + bytes_taken, size - bytes_taken, &key, &bytes_taken) != 0) {
		return 0;
	}
	char key_string[17];
	u64_to_hex(key, key_string);

	uint64_t iv;
	if (take_u64(data + bytes_taken, size - bytes_taken, &iv, &bytes_taken) != 0) {
		return 0;
	}
	char iv_string[17];
	u64_to_hex(iv, iv_string);

	char *file_path = buf_to_file(data + bytes_taken, size - bytes_taken);
	if (file_path == NULL) {
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-d", "-i", file_path, "-o", "/dev/null", "-k", key_string, "-v", iv_string, NULL};
	(void)cmd_des_cbc(args);

	delete_file(file_path);
	return 0;
}

int fuzz_des_cbc_decode_pass(uint8_t const *data, size_t size) {
	size_t bytes_taken = 0;

	uint8_t pass_len;
	char *pass = take_string(data + bytes_taken, size - bytes_taken, 16, &pass_len, &bytes_taken);
	if (pass == NULL) {
		return 0;
	}

	char *file_path = buf_to_file(data + bytes_taken, size - bytes_taken);
	if (file_path == NULL) {
		free(pass);
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-d", "-i", file_path, "-o", "/dev/null", "-p", pass, NULL};
	(void)cmd_des_cbc(args);

	free(pass);
	delete_file(file_path);
	return 0;
}

int fuzz_des_cbc_decode_pass_salt(uint8_t const *data, size_t size) {
	size_t bytes_taken = 0;

	uint8_t pass_len;
	char *pass = take_string(data + bytes_taken, size - bytes_taken, 16, &pass_len, &bytes_taken);
	if (pass == NULL) {
		return 0;
	}
	uint64_t salt;
	char salt_string[17];
	if (take_u64(data + bytes_taken, size - bytes_taken, &salt, &bytes_taken) == 0) {
		free(pass);
		return 0;
	}
	u64_to_hex(salt, salt_string);

	char *file_path = buf_to_file(data + bytes_taken, size - bytes_taken);
	if (file_path == NULL) {
		free(pass);
		exit(EXIT_FAILURE);
	}

	char *args[] = {"-d", "-i", file_path, "-o", "/dev/null", "-p", pass, "-s", salt_string, NULL};
	(void)cmd_des_cbc(args);

	free(pass);
	delete_file(file_path);
	return 0;
}

int LLVMFuzzerTestOneInput(uint8_t const *data, size_t size) {
	return fuzz_md5(data, size);
	// return fuzz_sha256(data, size);
	// return fuzz_base64_encode(data, size);
	// return fuzz_base64_decode(data, size);
	// return fuzz_des_ecb_encode_pass(data, size);
	// return fuzz_des_ecb_encode_key(data, size);
	// return fuzz_des_ecb_decode_key(data, size);
	// return fuzz_des_ecb_decode_pass(data, size);
	// return fuzz_des_ecb_decode_pass_salt(data, size);
	// return fuzz_des_cbc_encode_pass(data, size);
	// return fuzz_des_cbc_encode_key_iv(data, size);
	// return fuzz_des_cbc_decode_key_iv(data, size);
	// return fuzz_des_cbc_decode_pass(data, size);
	// return fuzz_des_cbc_decode_pass_salt(data, size);
}
