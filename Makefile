NAME := ft_ssl

SRCDIR := src
SOURCES := $(shell find $(SRCDIR) -name '*.c' -not -name '*_bonus.c' -not -name 'test.c')
ifeq ($(FUZZ),1)
	SOURCES := $(filter-out $(SRCDIR)/main.c,$(SOURCES)) $(SRCDIR)/fuzz.c
endif
OBJDIR := obj
OBJECTS := $(addprefix $(OBJDIR)/, $(SOURCES:c=o))

# ifdef BONUS
# OBJECTS += $(OBJECTS_BONUS)
# endif

INCLUDES := $(addprefix -I,$(sort $(dir $(shell find $(SRCDIR) -name '*.h' -not -name '*_bonus.h'))))
CFLAGS := -Wall -Wextra -Werror $(INCLUDES)
LFLAGS := -lbsd

ifdef SANITIZE
	SAN := $(SANITIZE)
endif
ifndef SAN
	SAN := 0
endif
ifneq ($(SAN),0)
	SANITIZERS := address,leak,undefined,integer,implicit-conversion,local-bounds,float-divide-by-zero,nullability
	CFLAGS += -fsanitize=$(SANITIZERS) -fno-omit-frame-pointer -fno-sanitize-recover=all
	LFLAGS += -fsanitize=$(SANITIZERS) -fno-omit-frame-pointer -fno-sanitize-recover=all
	DEBUG := 1
endif
ifeq ($(FUZZ),1)
	CFLAGS += -fsanitize=fuzzer
	LFLAGS += -fsanitize=fuzzer
endif
ifndef DEBUG
	DEBUG := 0
endif
ifneq ($(DEBUG),0)
	CFLAGS += -g
	LFLAGS += -g
endif


$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(NAME): $(OBJECTS)
	$(CC) $(LFLAGS) $(OBJECTS) -o $@

.GOAL: all
.PHONY: all
all: $(NAME)

.PHONY: clean
clean:
	rm -rf $(OBJDIR)

.PHONY: fclean
fclean: clean
	rm -f $(NAME)

.PHONY: fclean
fclean: clean
	rm -f $(NAME)
	# rm -f $(TEST_NAME)

.PHONY: re
re: fclean all

.PHONY: bonus
bonus:
	$(MAKE) BONUS=1

.PHONY: re_bonus
re_bonus:
	$(MAKE) BONUS=1 re

valgrind:
	$(MAKE) re DEBUG=1 SAN=0

fuzz:
	$(MAKE) re SAN=1 FUZZ=1

# .PHONY: test
# test: all
# ifdef BONUS
# 	$(CC) $(if $(DEBUG), -g) -Wall -Wextra -Werror -DBONUS=1 src/main.c -lasm -L. -o $(TEST_NAME)
# else
# 	$(CC) $(if $(DEBUG), -g) -Wall -Wextra -Werror src/main.c -lasm -L. -o $(TEST_NAME)
# endif
# 	@echo
# 	@./$(TEST_NAME)
#
# .PHONY: bonus_test
# bonus_test:
# 	$(MAKE) BONUS=1 test
#
# .PHONY: re_test
# re_test: fclean test
#
# .PHONY: re_bonus_test
# re_bonus_test:
# 	$(MAKE) BONUS=1 re_test
