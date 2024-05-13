CC=g++
WARNING_FLAGS=-Wall -Wextra -Wpedantic -Wshadow -Wno-stringop-overflow
CFLAGS= -O2 -march=native $(WARNING_FLAGS) -D__LINUX__ -D__X64__ -I./sha3 -std=c++11 -I./ntl/include
CFLAGS_DEBUG= -g -march=native $(WARNING_FLAGS) -D__LINUX__ -D__X64__ -I./sha3 -fsanitize=address -fsanitize=undefined -I./ntl/include
NISTKATFLAGS = -Wno-unused-but-set-variable -Wno-unused-parameter -Wno-unused-result -Wno-error=write-strings -fpermissive
FLINTLIB=libflint.so.19.0.0
SHA3LIB=libshake.a
PICNIC_PATH=Picnic
FLINT_PATH=flint
SHA3_PATH=$(PICNIC_PATH)/sha3
LDFLAGS= $(SHA3_PATH)/$(SHA3LIB) ntl/src/.libs/libntl.so

SOURCES= $(PICNIC_PATH)/picnic_impl.c $(PICNIC_PATH)/picnic3_impl.c $(PICNIC_PATH)/picnic.c $(PICNIC_PATH)/lowmc_constants.c
PICNIC_OBJECTS= $(PICNIC_PATH)/picnic_impl.o $(PICNIC_PATH)/picnic3_impl.o $(PICNIC_PATH)/picnic.o $(PICNIC_PATH)/lowmc_constants.o $(PICNIC_PATH)/hash.o $(PICNIC_PATH)/picnic_types.o $(PICNIC_PATH)/tree.o
PICNIC_LIB=$(PICNIC_PATH)/libpicnic.a
PQTR=pqtr

all: $(SHA3LIB) $(SOURCES) $(PICNIC_LIB) $(PQTR)

$(SHA3LIB):
		$(MAKE) -C $(SHA3_PATH) 

# debug build
debug: CFLAGS = $(CFLAGS_DEBUG)
debug: all

$(PQTR): $(PQTR).c $(PICNIC_LIB)
	    $(CC) $(NISTKATFLAGS) $(@).c $(CFLAGS) $(PICNIC_LIB) -o $@ $(LDFLAGS)

.c.o: 
	    $(CC) -c $(CFLAGS) $< -o $@

$(PICNIC_LIB): $(PICNIC_OBJECTS)
	ar rcs $@ $^

clean:
	    rm $(PQTR) *.o 2>/dev/null || true
	    rm $(PICNIC_LIB) 2>/dev/null || true
	    $(MAKE) -C $(SHA3_PATH) clean
