CPPFLAGS ?=
override CPPFLAGS += -D_GNU_SOURCE -I../src/include/
CFLAGS ?= -g -O2
XCFLAGS =
override CFLAGS += -D_GNU_SOURCE -Wall -L../src/

include ../Makefile.quiet

ifneq ($(MAKECMDGOALS),clean)
include ../config-host.mak
endif

all_targets += io_uring-test io_uring-cp link-cp io_uring-bpf-asm

ifdef CONFIG_HAVE_UCONTEXT
all_targets += ucontext-cp
endif

all: $(all_targets)

test_srcs := io_uring-test.c io_uring-cp.c link-cp.c io_uring-bpf-asm.c

test_objs := $(patsubst %.c,%.ol,$(test_srcs))

io_uring-bpf-asm: XCFLAGS = -lelf -lz -lbpf

%: %.c
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -luring $(XCFLAGS)

clean:
	@rm -f $(all_targets) $(test_objs)
