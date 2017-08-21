CFLAGS= -O3 -ggdb -fno-stack-protector -fPIE -pie -Wall
ASFLAGS= --64 -ggdb
LDFLAGS= -nostdlib -shared

BINARY=dlng

HEADERS=$(wildcard *.h)
SOURCES=$(wildcard *.c *.S)
OBJECTS=$(patsubst %.c,%.o,$(patsubst %.S,%.o,$(SOURCES)))
VERSIONMAP=dlng.map

$(BINARY): $(OBJECTS)
	$(LD) -o $@ $(LDFLAGS) $+ --version-script $(VERSIONMAP)

%.o: %.S
	$(AS) -o $@ $(ASFLAGS) $<

%.o: %.c $(HEADERS)
	$(CC) -c -o $@ $(CFLAGS) $<

clean:
	rm -f $(BINARY) $(OBJECTS)

.PHONY: clean
