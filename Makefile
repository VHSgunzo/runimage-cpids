#  Makefile for cpids

CC := $(shell which musl-gcc)
CC := $(if $(CC),musl-gcc,gcc)
CFLAGS = -static -Wall -Wextra -Os -s -g0 -ffunction-sections -fdata-sections -fvisibility=hidden -fmerge-all-constants
LDFLAGS = --static -Wl,--gc-sections -Wl,--strip-all

cpids: cpids.c

clean:
	rm -f cpids
