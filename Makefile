# ziprec - Makefile (macOS / Linux / mingw)
# Windows MSVC build: see build_windows.bat / README.md

CC      ?= cc
CFLAGS  ?= -O3 -std=c11 -Wall -Wextra -Wno-unused-parameter -flto
LDFLAGS ?=
LDLIBS  ?=

UNAME_S := $(shell uname -s 2>/dev/null)
UNAME_M := $(shell uname -m 2>/dev/null)

ifeq ($(UNAME_S),Darwin)
  ifeq ($(UNAME_M),arm64)
    CFLAGS += -mcpu=native
  endif
endif
ifeq ($(UNAME_S),Linux)
  ifeq ($(UNAME_M),x86_64)
    CFLAGS += -march=native
  endif
  LDLIBS += -lpthread
endif

SRC := src/main.c src/zipfile.c src/crypto.c src/inflate.c src/gen.c \
       src/engine.c src/ckpt.c src/export.c src/gpu.c src/ext.c src/i18n.c

ziprec: $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f ziprec

.PHONY: clean
