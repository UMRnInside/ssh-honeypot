#define VERSION  "0.3.0"

#define LOGFILE      "ssh-honeypot.log"          /* default log location */
#define PIDFILE      "ssh-honeypot.pid"          /* default pid file location */
#define PORT         22                          /* default port */
#define BINDADDR     "0.0.0.0"                   /* default bind address */
#define TIMEOUT      60                          /* login timeout in seconds */
#define JSON_LOGFILE "ssh-honeypot.json.log"     /* default json log location */
#define JSON_SERVER  "127.0.0.1"                 /* send json to this host */
#define JSON_PORT    55555                       /* send json to this port */
#define KEY_PREFIX   "ssh-honeypot"              /* <prefix>.<key_type> e.g.: ssh-honeypot.rsa */
