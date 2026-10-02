[0.1.0]

* Added JSON logging. This will log to a file and send UDP packets of 
  connections and failed logins to a remote host. This is meant to send data
  to an ELK or Splunk listener.

[0.2.0]

* Added HASSH, requires libpcap

[0.3.0]

* Added Ed25519/ECDSA host keys.
* REMOVED '-r <rsakey>' option, use '-K <prefix>' instead.
  This is host keys' path prefix.
  e.g.: '-K /path/to/keys' will read 
  /path/to/keys.rsa for RSA, /path/to/keys.ecdsa for ECDSA,
  and /path/to/keys.ed25519 for Ed25519.
* Updated built-in banners list.
