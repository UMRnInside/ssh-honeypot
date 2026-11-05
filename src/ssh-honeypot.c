/* ssh-honeypot -- by Daniel Roberson (daniel(a)planethacker.net) 2016-2022
 *
 * TODO: keep fp open for log_entry; reload on HUP
 * TODO: config files
 * TODO: add more banners
 * TODO: log public keys.
 *       https://github.com/jeroen/libssh/blob/master/examples/ssh_server_fork.c
 * TODO: ipv6
 * TODO: do not print non-printable characters in usernames/passwords.
 */

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <poll.h>
#include <syslog.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include <json-c/json.h>

#include "config.h"


/* Globals */
char           *logfile             = LOGFILE;
char           *pidfile             = PIDFILE;
char           *host_key_prefix     = KEY_PREFIX;
char           *bindaddr            = BINDADDR;
uint16_t		port         		= PORT;
bool            console_output      = true;
bool            daemonize           = false;
bool            use_syslog          = false;
bool            logging             = true;
bool            json_logging_file   = false;
bool            json_logging_server = false;
char           *json_logfile        = JSON_LOGFILE;
char           *json_server         = JSON_SERVER;
unsigned short  json_port           = JSON_PORT;
bool            verbose             = false;
int             json_sock;
char            hostname[MAXHOSTNAMELEN];

#define num_key_types 3
const char key_types[num_key_types][8] = {"ed25519", "ecdsa", "rsa"};
char* host_keys[num_key_types] = {NULL, NULL, NULL};

/* Per-connection state for the single-process event loop. */
struct client_session {
	ssh_session			session;
	ssh_event			event;
	struct ssh_server_callbacks_struct callbacks;
	char				ip[INET6_ADDRSTRLEN];
	uint16_t			sport;
	uint16_t			dport;
	time_t				last_activity;
	bool				kex_done;
	struct client_session *next;
};

static struct client_session	*clients    = NULL;
static long					session_timeout = TIMEOUT;

/* Banners */
static struct banner_info_s {
	const char	*str, *info;
} banners[] = {
	{"",  "No banner"},
	{"OpenSSH_7.6p1 Ubuntu-4ubuntu0.3", "Ubuntu 18.04"},
	{"OpenSSH_8.2p1 Ubuntu-4ubuntu0.4", "Ubuntu 20.04"},
	{"OpenSSH_6.6.1",                   "openSUSE 42.1"},
	{"OpenSSH_9.2p1 Debian-2+deb12u10", "Debian 12"},
	{"OpenSSH_10.0p2 Debian-7+deb13u4", "Debian 13.6"},
	{"OpenSSH_7.5",                     "pfSense 2.4.4-RELEASE-p3"},
	{"dropbear_2014.63",                "dropbear 2014.63"},
	{"OpenSSH_6.7p1 Raspbian-5+deb8u4", "Raspberry Pi (old)"},
	{"OpenSSH_8.4p1 Raspbian-5+b1"    , "Raspberry Pi (Raspbian 11)"},
	{"ROSSSH",                          "MikroTik"},
};

const size_t num_banners = sizeof(banners) / sizeof(*banners);


/* usage() -- prints out usage instructions and exits the program
 */
static void usage(const char *progname) {
	fprintf(stderr, "ssh-honeypot %s\n\n", VERSION);
	//TODO check make sure all of this actually jives with reality.
	fprintf(stderr, "usage: %s "
			"[-?h -p <port> -a <address> -b <index> -l <file> -K <prefix> "
			"-f <file> -u <user>]\n",
			progname);
	fprintf(stderr, "\t-?/-h\t\t-- this help menu\n");
	fprintf(stderr, "\t-p <port>\t-- listen port\n");
	fprintf(stderr, "\t-a <address>\t-- IP address to bind to\n");
	fprintf(stderr, "\t-d\t\t-- daemonize process\n");
	fprintf(stderr, "\t-L\t\t-- toggle logging to a file. Default: %s\n",
			logging ? "on" : "off");
	fprintf(stderr, "\t-l <file>\t-- log file\n");
	fprintf(stderr, "\t-s\t\t-- toggle syslog usage. Default: %s\n",
			use_syslog ? "on" : "off");
	fprintf(stderr, "\t-t\t\t-- authentication timeout. Default: %d\n",
			TIMEOUT);
	fprintf(stderr, "\t-K <prefix>\t-- host key prefix: loads <prefix>.ed25519 <prefix>.ecdsa <prefix>.rsa as host keys\n");
	fprintf(stderr, "\t-f <file>\t-- specify location to PID file\n");
	fprintf(stderr, "\t-b\t\t-- list available banners\n");
	fprintf(stderr, "\t-b <string>\t-- specify banner string (max 255 characters)\n");
	fprintf(stderr, "\t-i <index>\t-- specify banner index\n");
	fprintf(stderr, "\t-u <user>\t-- user to setuid() to after bind()\n");
	fprintf(stderr, "\t-j <file>\t-- path to JSON logfile\n");
	fprintf(stderr, "\t-J <address>\t-- server to send JSON logs\n");
	fprintf(stderr, "\t-P <port>\t-- port to send JSON logs\n");
	fprintf(stderr, "\t-v\t\t-- verbose log output\n");

	exit(EXIT_FAILURE);
}


/* pr_banners() -- prints out a list of available banner options
 */
static void pr_banners() {
	fprintf(stderr, "Available banners: [index] banner (description)\n");

	for (size_t i = 0; i < num_banners; i++) {
		struct banner_info_s	*banner = banners + i;
		fprintf(stderr, "[%zu] %s (%s)\n", i, banner->str, banner->info);
	}

	fprintf(stderr, "Total banners: %zu\n", num_banners);
}


/* sockprintf() -- send formatted data to a socket
 */
static int sockprintf(int s, const char *fmt, ...) {
	int		n;
	char		buf[8192] = {0};
	va_list	vl;

	va_start(vl, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, vl);
	va_end(vl);

	return send(s, buf, n, 0);
}


/* log_entry() -- adds timestamped log entry
 *             -- displays output to stdout if console_output is true
 */
static void log_entry(const char *fmt, ...) {
	FILE		*fp;
	time_t		t;
	va_list	va;
	char		*timestr;
	char		buf[1024];


	time(&t);
	timestr = strtok(ctime(&t), "\n"); // remove newline

	va_start(va, fmt);
	vsnprintf(buf, sizeof(buf), fmt, va);
	va_end(va);

	if (logging) {
		if ((fp = fopen(logfile, "a+")) == NULL) {
			fprintf(stderr, "Unable to open log file %s: %s\n", logfile, strerror(errno));
		} else {
			fprintf(fp, "[%s] %s\n", timestr, buf);
			fclose(fp);
		}
	}

	if (use_syslog)
		syslog(LOG_INFO | LOG_AUTHPRIV, "%s", buf);

	if (console_output)
		printf("[%s] %s\n", timestr, buf);
}


/* log_entry_fatal() -- log a message, then exit with EXIT_FAILURE
 */
void log_entry_fatal(const char *fmt, ...) {
	va_list	vl;

	va_start(vl, fmt);
	log_entry(fmt, vl);
	va_end(vl);

	exit(EXIT_FAILURE);
}


/* json_log() -- log JSON formatted data to a file
 */
static void json_log(const char *msg) {
	FILE	*fp;

	fp = fopen(json_logfile, "a");

	if (fp == NULL)
		log_entry_fatal("FATAL: Unable to open JSON log file %s: %s",
						json_logfile,
						strerror(errno));

	fprintf(fp, "%s\n", msg);
	fclose(fp);
}


/* json_log_creds() -- log username/password in JSON format
 */
static void json_log_creds(const char *ip, const char *user, const char *pass) {
	char			*message;

	json_object		*jobj     = json_object_new_object();
	json_object		*j_time   = json_object_new_int(time(NULL));
	json_object		*j_host   = json_object_new_string(hostname);
	json_object		*j_client = json_object_new_string(ip);
	json_object		*j_user   = json_object_new_string(user);
	json_object		*j_pass   = json_object_new_string(pass);
	json_object		*j_event  = json_object_new_string("ssh-honeypot-auth");

	json_object_object_add(jobj, "event", j_event);
	json_object_object_add(jobj, "time", j_time);
	json_object_object_add(jobj, "host", j_host);
	json_object_object_add(jobj, "client", j_client);
	json_object_object_add(jobj, "user", j_user);
	json_object_object_add(jobj, "pass", j_pass);

	message = (char *)json_object_to_json_string(jobj);

	if (json_logging_file)
		json_log(message);

	if (json_logging_server)
		sockprintf(json_sock, "%s\r\n", message);

	json_object_put(jobj);
}


/* json_log_kex_error() -- log connections in JSON format
 */
static void json_log_kex_error(const char *ip) {
	char			*message;

	json_object		*jobj     = json_object_new_object();
	json_object		*j_time   = json_object_new_int(time(NULL));
	json_object		*j_host   = json_object_new_string(hostname);
	json_object		*j_client = json_object_new_string(ip);
	json_object		*j_event  = json_object_new_string("ssh-honetpot-kexerror");

	json_object_object_add(jobj, "event", j_event);
	json_object_object_add(jobj, "time", j_time);
	json_object_object_add(jobj, "host", j_host);
	json_object_object_add(jobj, "client", j_client);

	message = (char *)json_object_to_json_string(jobj);

	if (json_logging_file)
		json_log(message);

	if (json_logging_server)
		sockprintf(json_sock, "%s\r\n", message);

	json_object_put(jobj);
}


/* json_log_session() - log information about client sessions
 */
static void json_log_session(const char *client_ip,
							 const char *banner_c,
							 const char *banner_s,
							 const uint16_t sport,
							 const uint16_t dport,
							 const char *kex_algo,
							 const char *cipher_in,
							 const char *cipher_out,
							 const char *hmac_in,
							 const char *hmac_out) {
	char			*message;
	json_object	*jobj         = json_object_new_object();
	json_object	*j_time       = json_object_new_int(time(NULL));
	json_object	*j_host       = json_object_new_string(hostname);
	json_object *j_dport      = json_object_new_int(dport);
	json_object	*j_client     = json_object_new_string(client_ip);
	json_object *j_sport      = json_object_new_int(sport);
	json_object	*j_event      = json_object_new_string("ssh-honeypot-session");
	json_object	*j_banner_c   = json_object_new_string(banner_c);
	json_object	*j_banner_s   = json_object_new_string(banner_s);
	json_object	*j_kex_algo   = json_object_new_string(kex_algo);
	json_object	*j_cipher_in  = json_object_new_string(cipher_in);
	json_object	*j_cipher_out = json_object_new_string(cipher_out);
	json_object	*j_hmac_in    = json_object_new_string(hmac_in);
	json_object	*j_hmac_out   = json_object_new_string(hmac_out);

	json_object_object_add(jobj, "event", j_event);
	json_object_object_add(jobj, "time", j_time);
	json_object_object_add(jobj, "host", j_host);
	json_object_object_add(jobj, "dport", j_dport);
	json_object_object_add(jobj, "client", j_client);
	json_object_object_add(jobj, "sport", j_sport);
	json_object_object_add(jobj, "client_banner", j_banner_c);
	json_object_object_add(jobj, "server_banner", j_banner_s);
	json_object_object_add(jobj, "kex_algo", j_kex_algo);
	json_object_object_add(jobj, "cipher_in", j_cipher_in);
	json_object_object_add(jobj, "cipher_out", j_cipher_out);
	json_object_object_add(jobj, "hmac_in", j_hmac_in);
	json_object_object_add(jobj, "hmac_out", j_hmac_out);

	message = (char *)json_object_to_json_string(jobj);

	if (json_logging_file)
		json_log(message);

	if (json_logging_server)
		sockprintf(json_sock, "%s\r\n", message);

	json_object_put(jobj);
}


/* fill_client_address() -- copy the peer address and source port into client */
static void fill_client_address(struct client_session *client) {
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	const void *src = NULL;

	snprintf(client->ip, sizeof(client->ip), "%s", "unknown");
	client->sport = 0;

	if (getpeername(ssh_get_fd(client->session), (struct sockaddr *)&addr, &len) != 0)
		return;

	if (addr.ss_family == AF_INET)
		src = &((struct sockaddr_in *)&addr)->sin_addr;
	else if (addr.ss_family == AF_INET6)
		src = &((struct sockaddr_in6 *)&addr)->sin6_addr;
	else
		return;

	if (inet_ntop(addr.ss_family, src, client->ip, sizeof(client->ip)) == NULL)
		snprintf(client->ip, sizeof(client->ip), "%s", "unknown");

	if (addr.ss_family == AF_INET)
		client->sport = ntohs(((struct sockaddr_in *)&addr)->sin_port);
	else
		client->sport = ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
}


/* log_session_info() -- log negotiated session details once kex completes */
static void log_session_info(struct client_session *client) {
	ssh_session session = client->session;
	const char *banner_c   = ssh_get_clientbanner(session);
	const char *banner_s   = ssh_get_serverbanner(session);
	const char *kex_algo   = ssh_get_kex_algo(session);
	const char *cipher_in  = ssh_get_cipher_in(session);
	const char *cipher_out = ssh_get_cipher_out(session);
	const char *hmac_in    = ssh_get_hmac_in(session);
	const char *hmac_out   = ssh_get_hmac_out(session);

	if (banner_c == NULL)   banner_c = "";
	if (banner_s == NULL)   banner_s = "";
	if (kex_algo == NULL)   kex_algo = "";
	if (cipher_in == NULL)  cipher_in = "";
	if (cipher_out == NULL) cipher_out = "";
	if (hmac_in == NULL)    hmac_in = "";
	if (hmac_out == NULL)   hmac_out = "";

	if (json_logging_file || json_logging_server) {
		json_log_session(client->ip,
						 banner_c,
						 banner_s,
						 client->sport,
						 client->dport,
						 kex_algo,
						 cipher_in,
						 cipher_out,
						 hmac_in,
						 hmac_out);
	}

	if (verbose) {
		log_entry("Session:  %s|%s|%s|%s|%s|%s|%s",
				  banner_c,
				  banner_s,
				  kex_algo,
				  cipher_in,
				  cipher_out,
				  hmac_in,
				  hmac_out);
	}
}


/* auth_password_cb() -- log every password attempt and always deny it */
static int auth_password_cb(ssh_session session,
							const char *user,
							const char *password,
							void *userdata) {
	struct client_session *client = userdata;
	const char *username = user != NULL ? user : "";
	const char *pass     = password != NULL ? password : "";

	(void)session;

	if (json_logging_file || json_logging_server)
		json_log_creds(client->ip, username, pass);

	log_entry("%s %s %s", client->ip, username, pass);

	return SSH_AUTH_DENIED;
}


/* service_request_cb() -- allow the ssh-userauth service */
static int service_request_cb(ssh_session session,
							  const char *service,
							  void *userdata) {
	(void)session;
	(void)service;
	(void)userdata;

	return 0;
}


/* channel_open_request_session_cb() -- keep clients out of a shell */
static ssh_channel channel_open_request_session_cb(ssh_session session,
												   void *userdata) {
	(void)session;
	(void)userdata;

	return NULL;
}


/* client_kex_done() -- transition a client out of key exchange */
static void client_kex_done(struct client_session *client) {
	if (client->kex_done)
		return;

	client->kex_done = true;
	log_session_info(client);
}


/* client_advance() -- process pending socket events for one client.
 * Returns false when the client should be removed.
 */
static bool client_advance(struct client_session *client, bool ready) {
	int rc;

	if (ready)
		client->last_activity = time(NULL);

	if (!client->kex_done) {
		if (ready) {
			rc = ssh_handle_key_exchange(client->session);
			if (rc == SSH_OK) {
				client_kex_done(client);
			} else if (rc != SSH_AGAIN) {
				if (verbose)
					log_entry("%s Error exchanging keys: %s",
							  client->ip,
							  ssh_get_error(client->session));

				if (json_logging_file || json_logging_server)
					json_log_kex_error(client->ip);

				return false;
			}
		}
	}

	if (client->kex_done && ready) {
		rc = ssh_event_dopoll(client->event, 0);
		if (rc == SSH_ERROR)
			return false;
	}

	if (ssh_get_status(client->session) & (SSH_CLOSED | SSH_CLOSED_ERROR))
		return false;

	if (session_timeout > 0 &&
		time(NULL) - client->last_activity >= session_timeout) {
		if (verbose)
			log_entry("%s Session timed out", client->ip);

		return false;
	}

	return true;
}


/* client_unlink() -- remove a client from the global list */
static void client_unlink(struct client_session *client) {
	struct client_session **link = &clients;

	while (*link != NULL) {
		if (*link == client) {
			*link = client->next;
			return;
		}

		link = &(*link)->next;
	}
}


/* client_free() -- remove a client from the event loop and free it */
static void client_free(struct client_session *client) {
	client_unlink(client);

	if (client->event != NULL) {
		/* Move the session's poll handles back before freeing the event. */
		ssh_event_free(client->event);
	}

	ssh_disconnect(client->session);
	ssh_free(client->session);
	free(client);
}


/* client_setup() -- take ownership of a newly accepted session */
static void client_setup(ssh_session session) {
	struct client_session *client;
	int rc;

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		log_entry("ERROR: calloc(): %s", strerror(errno));
		ssh_disconnect(session);
		ssh_free(session);
		return;
	}

	client->session = session;
	client->last_activity = time(NULL);
	client->dport   = port;

	ssh_set_blocking(client->session, 0);
	fill_client_address(client);

	memset(&client->callbacks, 0, sizeof(client->callbacks));
	client->callbacks.userdata = client;
	client->callbacks.auth_password_function = auth_password_cb;
	client->callbacks.service_request_function = service_request_cb;
	client->callbacks.channel_open_request_session_function = channel_open_request_session_cb;
	ssh_callbacks_init(&client->callbacks);
	ssh_set_server_callbacks(client->session, &client->callbacks);
	ssh_set_auth_methods(client->session, SSH_AUTH_METHOD_PASSWORD);

	client->event = ssh_event_new();
	if (client->event == NULL) {
		log_entry("ERROR: ssh_event_new(): %s", strerror(errno));
		ssh_disconnect(client->session);
		ssh_free(client->session);
		free(client);
		return;
	}

	/* Send the server banner and start key exchange. With a nonblocking
	 * session this returns SSH_AGAIN and the event loop finishes the job.
	 */
	rc = ssh_handle_key_exchange(client->session);
	if (rc == SSH_ERROR) {
		if (verbose)
			log_entry("%s Error exchanging keys: %s",
					  client->ip,
					  ssh_get_error(client->session));

		if (json_logging_file || json_logging_server)
			json_log_kex_error(client->ip);

		ssh_event_free(client->event);
		ssh_disconnect(client->session);
		ssh_free(client->session);
		free(client);
		return;
	}

	if (ssh_event_add_session(client->event, client->session) == SSH_ERROR) {
		log_entry("ERROR: ssh_event_add_session(): %s",
				  ssh_get_error(client->session));
		ssh_event_free(client->event);
		ssh_disconnect(client->session);
		ssh_free(client->session);
		free(client);
		return;
	}

	if (rc == SSH_OK)
		client_kex_done(client);

	client->next = clients;
	clients = client;
}


/* client_accept() -- drain pending connections from the listening socket */
static void client_accept(ssh_bind bind) {
	for (;;) {
		ssh_session session = ssh_new();
		int saved_errno;

		if (session == NULL) {
			log_entry("ERROR: ssh_new(): %s", strerror(errno));
			break;
		}

		if (ssh_bind_accept(bind, session) == SSH_ERROR) {
			saved_errno = errno;
			ssh_free(session);

			if (saved_errno == EINTR)
				continue;

			if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK)
				break;

			log_entry("ERROR: ssh_bind_accept(): %s", ssh_get_error(bind));
			break;
		}

		client_setup(session);
	}
}


/* write_pid_file() -- writes PID to PIDFILE
 */
static void write_pid_file(char *path, pid_t pid) {
	FILE	*fp;

	fp = fopen(path, "w");

	if (fp == NULL)
		log_entry_fatal("FATAL: Unable to open PID file %s: %s\n",
						path,
						strerror(errno));

	fprintf(fp, "%d", pid);
	fclose(fp);
}


/* drop_privileges() -- drops privileges to specified user/group
 */
void drop_privileges(char *username) {
	struct passwd	*pw;
	struct group	*grp;


	pw = getpwnam(username);
	if (pw == NULL)
		log_entry_fatal("FATAL: Username does not exist: %s\n", username);

	grp = getgrgid(pw->pw_gid);
	if (grp == NULL)
		log_entry_fatal("FATAL: Unable to determine groupfor %d: %s\n",
						pw->pw_gid,
						strerror(errno));

	/* chown logfile so this user can use it */
	if (chown(logfile, pw->pw_uid, pw->pw_gid) == -1)
		log_entry_fatal("FATAL: Unable to set permissions for log file %s: %s\n",
						logfile,
						strerror(errno));

	/* drop group first */
	if (setgid(pw->pw_gid) == -1)
		log_entry_fatal("FATAL: Unable to drop group permissions to %s: %s\n",
						grp->gr_name,
						strerror(errno));

	/* drop user privileges */
	if (setuid (pw->pw_uid) == -1)
		log_entry_fatal("FATAL: Unable to drop user permissions to %s: %s\n",
						username,
						strerror(errno));
}


/* main() -- main entry point of program
 */
int main(int argc, char *argv[]) {
	pid_t			pid;
	int				opt;
	unsigned short	banner_index = 1;
	const char		*banner      = banners[1].str;
	char			*username    = NULL;
	ssh_bind		sshbind;
	int             i;
	int             result;
	int             keys_loaded  = 0;
	size_t          prefix_len   = strlen(KEY_PREFIX);


	while ((opt = getopt(argc, argv, "vh?p:dLl:a:b:i:K:f:t:su:j:J:P:")) != -1) {
		switch (opt) {
		case 'p': /* Listen port */
			port = atoi(optarg);
			break;

		case 'd': /* Daemonize */
			daemonize = true;
			console_output = false;
			break;

		case 'L': /* Toggle logging to a file */
			logging = logging ? false : true;
			break;

		case 'l': /* Log file path */
			logfile = optarg;
			break;

		case 'a': /* IP to bind to */
			bindaddr = optarg;
			break;

		case 'K': /* Host keys' path prefix */
			host_key_prefix = optarg;
			prefix_len = strlen(host_key_prefix);
			break;

		case 'f': /* PID file location */
			pidfile = optarg;
			break;

		case 's': /* Toggle syslog */
			use_syslog = use_syslog ? false : true;
			break;

		case 't': /* Authentication timeout */
			session_timeout = atoi(optarg);
			break;

		case 'u': /* User to drop privileges to */
			username = optarg;
			break;

		case 'i': /* Set banner by index */
			banner_index = atoi(optarg);

			if (banner_index >= num_banners) {
				fprintf(stderr, "FATAL: Invalid banner index\n");
				exit(EXIT_FAILURE);
			}

			banner = banners[banner_index].str;
			break;

		case 'b': /* Specify banner string */
			banner = optarg;
			break;

		case 'j': /* JSON logfile */
			json_logging_file = true;
			json_logfile = optarg;
			break;

		case 'J': /* JSON server */
			json_logging_server = true;
			json_server = optarg;
			break;

		case 'P': /* JSON port */
			json_port = atoi(optarg);
			break;

		case '?': /* Print usage */
		case 'h':
			if (optopt == 'i' || optopt == 'b') {
				pr_banners();
				return EXIT_FAILURE;
			}
			usage(argv[0]);
			return EXIT_SUCCESS;

		case 'v': /* verbose output */
			verbose = true;
			break;

		default:
			usage(argv[0]);
		}
	}

	if (gethostname(hostname, sizeof(hostname)) == -1)
		log_entry_fatal("FATAL: gethostname(): %s\n", strerror(errno));

	if (json_logging_server) {
		struct sockaddr_in	s_addr;

		json_sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (json_sock < 0)
			log_entry_fatal("FATAL: socket(): %s\n", strerror(errno));

		bzero(&s_addr, sizeof(s_addr));
		s_addr.sin_family = AF_INET;
		s_addr.sin_addr.s_addr = inet_addr(json_server);
		s_addr.sin_port = htons(json_port);

		/* connect() UDP socket to avoid sendto() */
		if (connect(json_sock, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1)
			log_entry_fatal("FATAL: connect(): %s\n", strerror(errno));
	}

	if (daemonize) {
		pid = fork();

		if (pid < 0)
			log_entry_fatal("FATAL: fork(): %s\n", strerror(errno));

		else if (pid > 0) {
			write_pid_file(pidfile, pid);
			exit(EXIT_SUCCESS);
		}

		printf("ssh-honeypot %s started on port %d. PID %d\n",
			   VERSION,
			   port,
			   getpid());
	}

	log_entry("ssh-honeypot %s started on port %d. PID %d",
			  VERSION,
			  port,
			  getpid());

	sshbind = ssh_bind_new();
	if (sshbind == NULL)
		log_entry_fatal("FATAL: ssh_bind_new(): %s", strerror(errno));

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, bindaddr);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BANNER, banner);

	for (i=0;i<num_key_types;i++) {
		host_keys[i] = malloc(prefix_len + 16);
		if (host_keys[i] == NULL) {
			printf("FATAL: malloc() failed!\n");
			return EXIT_FAILURE;
		}
		snprintf(host_keys[i], prefix_len + 16, "%s.%s", host_key_prefix, key_types[i]);
		result = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, host_keys[i]);
		if (result == 0) {
			printf("INFO: loaded SSH host key (%s): %s\n", key_types[i], host_keys[i]);
			keys_loaded++;
		} else {
			printf("WARN: ssh_bind_options_set(HOSTKEY): %s\n", ssh_get_error(sshbind));
			printf("WARN: (path attempted: %s )\n", host_keys[i]);
		}
	}

	if (keys_loaded == 0) {
		printf("FATAL: no host keys found!\n");
		return EXIT_FAILURE;
	}

	if (ssh_bind_listen(sshbind) < 0) {
		if (daemonize) // TODO: show meaningful error if key isn't supplied
			printf("FATAL: ssh_bind_listen(): %s\n", ssh_get_error(sshbind));

		log_entry_fatal("FATAL: ssh_bind_listen(): %s", ssh_get_error(sshbind));
	}

	/* drop privileges */
	if (username != NULL)
		drop_privileges(username);

	/* Use a non-blocking listening socket so client_accept() can drain all
	 * pending connections without blocking the event loop.
	 */
	result = fcntl(ssh_bind_get_fd(sshbind), F_GETFL, 0);
	if (result != -1)
		fcntl(ssh_bind_get_fd(sshbind), F_SETFL, result | O_NONBLOCK);

	{
		struct pollfd *pollfds = NULL;
		struct client_session **pollclients = NULL;
		size_t pollcap = 0;

		for (;;) {
			struct client_session *client;
			size_t nclients = 0;
			size_t i = 0;
			int rc;

			for (client = clients; client != NULL; client = client->next)
				nclients++;

			if (nclients + 1 > pollcap) {
				size_t newcap = pollcap == 0 ? 16 : pollcap;

				while (newcap < nclients + 1)
					newcap *= 2;

				pollfds = realloc(pollfds,
								  newcap * sizeof(*pollfds));
				if (pollfds == NULL)
					log_entry_fatal("FATAL: realloc(): %s", strerror(errno));

				pollclients = realloc(pollclients,
									  newcap * sizeof(*pollclients));
				if (pollclients == NULL)
					log_entry_fatal("FATAL: realloc(): %s", strerror(errno));

				pollcap = newcap;
			}

			pollfds[0].fd = ssh_bind_get_fd(sshbind);
			pollfds[0].events = POLLIN;
			pollfds[0].revents = 0;

			for (client = clients; client != NULL; client = client->next) {
				int flags = ssh_get_poll_flags(client->session);

				pollclients[i] = client;
				pollfds[i + 1].fd = ssh_get_fd(client->session);
				pollfds[i + 1].events = POLLIN;
				if (flags & SSH_WRITE_PENDING)
					pollfds[i + 1].events |= POLLOUT;
				pollfds[i + 1].revents = 0;
				i++;
			}

			rc = poll(pollfds, i + 1, 500);
			if (rc < 0) {
				if (errno == EINTR)
					continue;

				log_entry("ERROR: poll(): %s", strerror(errno));
				break;
			}

			if (rc > 0 && (pollfds[0].revents & POLLIN))
				client_accept(sshbind);

			for (size_t j = 0; j < i; j++) {
				bool ready = pollfds[j + 1].revents != 0;

				if (!client_advance(pollclients[j], ready))
					client_free(pollclients[j]);
			}
		}

		free(pollfds);
		free(pollclients);
	}

	while (clients != NULL)
		client_free(clients);

	ssh_bind_free(sshbind);

	for (i=0;i<num_key_types;i++) {
		if (host_keys[i] != NULL) {
			free(host_keys[i]);
		}
	}
	return EXIT_SUCCESS;
}
