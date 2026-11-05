# SSH Honeypot

This unfortunately named program listens for incoming ssh connections
and logs the IP address, username, and password used by the
client. This is a low-interaction honeypot that does not allow malware
or attackers to login.

This was originally written to gather rudimentary intelligence on
brute force attacks and not meant for production usage.

This fork removes the original ssh-honeypot HASSH module and uses a
single-process event loop instead of forking a child process for every
client.

Nowadays, I mostly use this at attack/defend CTFs paired with sshunt:
https://github.com/droberson/sshunt

I set up sshunt to forward tools such as Hydra, Metasploit, and Ncrack
to ssh-honeypot and allow OpenSSH clients to connect to ssh normally.


## Quickstart

### Linux

Make sure headers/development packages are installed for:

- libssh
- libjson-c

```
apt install libssh-dev libjson-c-dev
```

Build and Run

```
make
ssh-keygen -t rsa -f ./ssh-honeypot.rsa
ssh-keygen -t ecdsa -f ./ssh-honeypot.ecdsa
ssh-keygen -t ed25519 -f ./ssh-honeypot.ed25519
./bin/ssh-honeypot -K ./ssh-honeypot
```

The `-K` option specifies the prefix for the SSH host key files. In this
example, ssh-honeypot looks for `./ssh-honeypot.ed25519`,
`./ssh-honeypot.ecdsa`, and `./ssh-honeypot.rsa`.

You can provide one, two, or all three key types. Each file must contain a
valid private host key of the type indicated by its extension. At least one
key file must be available; otherwise, ssh-honeypot will fail to start.

### OSX (experimental/unsupported)

_WARNING: I haven't tested JSON logging or anything really on OSX.
MacOS is officially unsupported as I do not own any Macs to test this
software with._

Make sure that xcode is up to date.

Install libssh and json-c

```
brew install libssh json-c
```

Specify MakefileOSX with make:

```
make -f MakefileOSX
```


### Docker (experimental)

Please take a look at our [Docker documentation](docker/README.md).


## Syslog facilities

As of version 0.0.5, this supports logging to syslog. This feature is
toggled with the -s flag. It is up to you to configure your syslog
facilities appropriately. This logs to LOG_AUTHPRIV which is typically
/var/log/auth.log. You may want to modify this to use one of the
LOG_LOCAL facilities if you are worried about password leakage.


## Dropping Privileges

As of version 0.0.8, you can drop root privileges of this program
after binding to a privileged port. You can now run this as _nobody_
on port 22 for example instead of root, but have to initially start it
as root:

```
sudo bin/ssh-honeypot -p 22 -u nobody
```

Beware that this chowns the logfile to the user specified as well.


## Changing the Banner

ssh-honeypot allows you to change the server's banner to blend in with
other hosts on your network or mimic a specific device.

List available banners

```
bin/ssh-honeypot -b
```

Set banner string

```
bin/ssh-honeypot -b "my banner string"
```

Set banner by index

```
bin/ssh-honeypot -i <banner index>
```


## JSON Logging

The `-j` CLI flag specifies the path to log results in JSON
format. This feature can make log analytics much easier because many
languages have robust JSON support.

JSON logs can be sent to a remote host. The `-J` and `-P` CLI flags
set the host and port to send logs in JSON to, respectively. At this
time, logs are transmitted using UDP and not encrypted.

This feature can be useful when running multiple ssh-honeypot
instances. Listeners can be created for Splunk and ElasticSearch to
ingest these logs and make them searchable.


## Systemd Integration

On Linux you can install ssh-honeypot as a Systemd service so that it
automatically runs at system startup:

```
make install
systemctl enable --now ssh-honeypot
```

The default unit runs as a systemd dynamic user, keeps file descriptors
for up to 16384 connections, and reads the host keys from
`/etc/ssh-honeypot` through `LoadCredential=`. `make install` generates
all three key types.

Before installing, check `ssh-honeypot.service` and modify it to run
with the options you want.
