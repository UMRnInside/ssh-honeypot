
#CFLAGS=-Wall -static-libgcc
CFLAGS=-Wall
LIBS=-lssh -ljson-c -lpcap -lssl -lcrypto

KEYS_DIR=/etc/ssh-honeypot

RSA=$(KEYS_DIR)/ssh-honeypot.rsa
ECDSA=$(KEYS_DIR)/ssh-honeypot.ecdsa
ED25519=$(KEYS_DIR)/ssh-honeypot.ed25519

.PHONY: install install-etc clean ssh-honeypot
ssh-honeypot: bin/ssh-honeypot

bin/ssh-honeypot:
	$(CC) $(CFLAGS) -o bin/ssh-honeypot src/ssh-honeypot.c $(LIBS)

clean:
	rm -f *~ src/*~ bin/ssh-honeypot src/*.o

install: ssh-honeypot install-etc $(RSA) $(ECDSA) $(ED25519)

$(KEYS_DIR):
	install -d /etc/ssh-honeypot

install-etc: $(KEYS_DIR)
	install -m 755 bin/ssh-honeypot /usr/local/bin/
	install -m 644 ssh-honeypot.service /etc/ssh-honeypot/
	ln -sf /etc/ssh-honeypot/ssh-honeypot.service /etc/systemd/system/
	@echo
	@echo "You can enable ssh-honeypot at startup with: systemctl enable --now ssh-honeypot"

$(RSA): $(KEYS_DIR)
	ssh-keygen -t rsa -f $(RSA) -N ''

$(ECDSA): $(KEYS_DIR)
	ssh-keygen -t ecdsa -f $(ECDSA) -N ''

$(ED25519): $(KEYS_DIR)
	ssh-keygen -t ed25519 -f $(ED25519) -N ''
