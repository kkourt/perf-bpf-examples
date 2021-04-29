
CLANG ?= clang
CLANG_FLAGS ?= -O2 -emit-llvm
LLC ?= llc
LLC_FLAGS ?= -march=bpf -filetype=obj

all: bpf.o help

bpf.o: bpf.c vmlinux.h
	$(CLANG) $(CLANG_FLAGS) -c bpf.c -o bpf.ll
	$(LLC) $(LLC_FLAGS) bpf.ll -o bpf.o

.PHONY: help
help:
	@echo perf command:
	@echo $$ sudo perf record -v -e bpf-output/no-inherit,name=evt/ -e ./bpf.o/map:channel.event=evt/ -a -- sleep 100
