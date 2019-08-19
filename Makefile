
CFLAGS := -Wall -Wmissing-prototypes -Wstrict-prototypes\
	  -fomit-frame-pointer -freg-struct-return -ggdb -g\
	  $(shell pkg-config --cflags glib-2.0)
	  #mbed_lib/libmbedcrypto.so mbed_lib/libmbedtls.so mbed_lib/libmbedx509.so
	  #-Lmbed_lib -llibmbedx509.so -libmbedtlx -libmbedcrypto\


#CFLAGS := -fomit-frame-pointer -freg-struct-return -O2
LIBS := -libverbs -lpthread -lrdmacm -libverbs -lmemcached \
		-lnuma -lmbedtls -lmbedcrypto -lm\
		$(shell pkg-config --libs glib-2.0)
SRCS := $(wildcard init*.c)
OBJS := $(SRCS:.c=.o)
DEPS := rsec_base.h server.h rsec.h rsec_struct.h rsec_util.h
all: $(OBJS)

clean:
	rm -f *.o

%.o: %.c 
	gcc ibsetup.c util.c server.c client.c rsec.c memcached.c rsec_control.c -o $@ $(CFLAGS) $(LIBS) $<
