LDLIBS=-lpcap

all: send-arp

send-arp: main.o arphdr.o ethhdr.o ip.o mac.o send-arp.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o
