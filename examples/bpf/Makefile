out_dir := .tmp
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
INCLUDES := -I$(out_dir)
CFLAGS := -g -O2 -Wall -L../../src/ -I../../src/include/
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
# LIBBPF := <linux-tree>/tools/lib/bpf/libbpf.a

include ../../Makefile.quiet

targets = uring \
	#

all: $(targets)

$(targets): %: $(out_dir)/%.o | $(out_dir) libbpf_target
	$(QUIET_CC)$(CC) $(CFLAGS) $^ -lelf -lz -luring $(LIBBPF) -o $@

$(patsubst %,$(out_dir)/%.o,$(targets)): %.o: %.skel.h

$(out_dir)/%.o: %.c $(wildcard %.h) | $(out_dir)
	$(QUIET_CC)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(out_dir)/%.skel.h: $(out_dir)/%.bpf.o | $(out_dir)
	$(BPFTOOL) gen skeleton $< > $@

$(out_dir)/%.bpf.o: %.bpf.c $(wildcard %.h) vmlinux | $(out_dir)
	$(QUIET_CC)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)	\
		     $(INCLUDES) -c $(filter %.c,$^) -o $@ &&		\
	$(LLVM_STRIP) -g $@

$(out_dir):
	mkdir -p $@

vmlinux:
ifeq (,$(wildcard ./vmlinux.h))
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./vmlinux.h
endif

libbpf_target:
ifndef LIBBPF
	$(error LIBBPF is undefined)
endif
	@

clean:
	$(Q)rm -rf $(out_dir) $(targets) ./vmlinux.h

.PHONY: all clean vmlinux libbpf_target
