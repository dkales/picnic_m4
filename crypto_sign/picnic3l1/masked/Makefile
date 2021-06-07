LIBPICNIC=libpicnic3-l1.a

SOURCES=$(wildcard *.c)
SOURCES_ASM=$(wildcard *.S)

WARNINGS=-Wall -Wextra -Wvla -Werror -Wredundant-decls
FULL_WARNINGS= $(WARNINGS) -Wconversion  -Wpedantic -Wmissing-prototypes

#Debug: build with symbols and without optimizations
#CFLAGS=-Og -g $(WARNINGS) -std=c99


# Build with optimizations
CFLAGS=-O3 $(WARNINGS) -std=c99 -I.

# Signature generation is randomized by default. The flag "-DMASKED_IMPL_DETERMINISTIC" makes it deterministic, 
# but is not SCA-secure. The flag is useful for debugging and required when running the KATs. 

# Build with optimizations and more warnings
#CFLAGS=-O3 $(FULL_WARNINGS) -std=c99 -fvisibility=default -I.


all: $(LIBPICNIC)
test: all example kats run_progs

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

$(LIBPICNIC): $(SOURCES:.c=.o) $(SOURCES_ASM:.S=.o)
	ar rcs $@ $^

kats: all tests/kats_test.c
	$(CC) $(CFLAGS) -DMASKED_IMPL_DETERMINISTIC -o kats.out tests/kats_test.c ${LIBPICNIC}

bench: all tests/bench.c tests/bench_timing.c tests/bench_utils.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -o bench.out tests/bench.c tests/bench_timing.c tests/bench_utils.c $(LIBPICNIC)

example: all tests/example.c 
	$(CC) $(CFLAGS) -D_GNU_SOURCE -o example.out tests/example.c $(LIBPICNIC)

run_progs: example kats bench
	echo "----\nRunning example and known-answer tests\n----"
	./example.out && ./kats.out && ./bench.out -i 10 7



clean:
	rm -f $(wildcard *.o) $(wildcard sha3/*.o) $(LIBPICNIC) kats.out bench.out example.out 
