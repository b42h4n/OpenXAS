#define _DEFAULT_SOURCE
#define _XOPEN_SOURCE 700

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>

#define XAS_GROUP    "wheel"   /* кому разрешено; закомментируй проверку в main, если не нужно */
#define MAX_ATTEMPTS 3
#define PASS_MAX     256
#define SAFE_PATH    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

/* Сравнение за постоянное время */
static int ct_equal(const char *a, const char *b)
{
	size_t la = strlen(a), lb = strlen(b);
	if (la != lb) return 0;
	unsigned char diff = 0;
	for (size_t i = 0; i < la; i++)
		diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
	return diff == 0;
}

/* Чтение пароля прямо из /dev/tty, а не из stdin. 0 = ок */
static int read_password(const char *prompt, char *buf, size_t size)
{
	int fd = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) return -1;

	struct termios old, noecho;
	if (tcgetattr(fd, &old) != 0) { close(fd); return -1; }
	noecho = old;
	noecho.c_lflag &= ~(tcflag_t)(ECHO | ECHONL);

	/* Блокируем сигналы, чтобы эхо гарантированно вернулось на место */
	sigset_t all, prev;
	sigfillset(&all);
	sigprocmask(SIG_BLOCK, &all, &prev);

	int rc = 0;
	if (tcsetattr(fd, TCSAFLUSH, &noecho) != 0) {
		sigprocmask(SIG_SETMASK, &prev, NULL);
		close(fd);
		return -1;
	}

	if (write(fd, prompt, strlen(prompt)) < 0) rc = -1;

	size_t n = 0;
	int too_long = 0;
	char c;
	while (rc == 0) {
		ssize_t r = read(fd, &c, 1);
		if (r < 0 && errno == EINTR) continue;
		if (r <= 0) { rc = -1; break; }      /* EOF / ошибка */
		if (c == '\n') break;
		if (n + 1 < size) buf[n++] = c;
		else too_long = 1;                    /* дочитываем до конца строки */
	}
	buf[n] = '\0';
	if (too_long) rc = -1;

	tcsetattr(fd, TCSAFLUSH, &old);
	if (write(fd, "\n", 1) < 0) { /* игнорируем */ }
	sigprocmask(SIG_SETMASK, &prev, NULL);
	close(fd);
	return rc;
}

/* 0 = пароль верный */
static int check_pass(const char *username, const char *password)
{
	struct spwd *sp = getspnam(username);
	if (!sp || !sp->sp_pwdp) return 1;

	char hash[256];
	if (strlen(sp->sp_pwdp) >= sizeof hash) return 1;
	strcpy(hash, sp->sp_pwdp);

	/* пустой или заблокированный аккаунт ("!", "*", "!!") — отказ */
	if (hash[0] == '\0' || hash[0] == '!' || hash[0] == '*') {
		explicit_bzero(hash, sizeof hash);
		return 1;
	}

	char *res = crypt(password, hash);
	int ok = 0;
	if (res && res[0] != '*')   /* "*0"/"*1" — признак ошибки crypt */
		ok = ct_equal(res, hash);

	explicit_bzero(hash, sizeof hash);
	return ok ? 0 : 1;
}

static int user_allowed(const struct passwd *pw)
{
	struct group *gr = getgrnam(XAS_GROUP);
	if (!gr) return 0;
	if (pw->pw_gid == gr->gr_gid) return 1;
	for (char **m = gr->gr_mem; m && *m; m++)
		if (strcmp(*m, pw->pw_name) == 0) return 1;
	return 0;
}

static int become_root(void)
{
	if (initgroups("root", 0) != 0) return -1;
	if (setresgid(0, 0, 0) != 0) return -1;
	if (setresuid(0, 0, 0) != 0) return -1;
	/* проверка, что вернуть привилегии назад нельзя/не нужно — все три uid = 0 */
	uid_t r, e, s;
	if (getresuid(&r, &e, &s) != 0 || r != 0 || e != 0 || s != 0) return -1;
	return 0;
}

static int clean_env(const char *term)
{
	char term_copy[128] = "";
	if (term) snprintf(term_copy, sizeof term_copy, "%s", term);

	if (clearenv() != 0) return -1;
	if (setenv("PATH", SAFE_PATH, 1) != 0) return -1;
	if (setenv("HOME", "/root", 1) != 0) return -1;
	if (setenv("USER", "root", 1) != 0) return -1;
	if (setenv("LOGNAME", "root", 1) != 0) return -1;
	if (term_copy[0] && setenv("TERM", term_copy, 1) != 0) return -1;
	return 0;
}

int main(int argc, char *argv[])
{
	/* Не оставляем чужие дескрипторы */
	int maxfd = getdtablesize();
	if (maxfd > 65536) maxfd = 65536;
	for (int fd = 3; fd < maxfd; fd++) close(fd);

	if (argc < 2) {
		fprintf(stderr, "Usage: xas <command> [args...]\n");
		return 1;
	}

	if (geteuid() != 0) {
		fprintf(stderr, "xas: must be installed setuid root\n");
		return 1;
	}

	umask(022);
	openlog("xas", LOG_PID, LOG_AUTHPRIV);

	/* Настоящий пользователь — по real uid, а не по getlogin() */
	struct passwd *pw = getpwuid(getuid());
	if (!pw) {
		fprintf(stderr, "xas: unknown user\n");
		return 1;
	}
	char username[256];
	if (strlen(pw->pw_name) >= sizeof username) return 1;
	strcpy(username, pw->pw_name);

	if (getuid() != 0) {
		if (!user_allowed(pw)) {
			syslog(LOG_WARNING, "%s: not in group %s, denied: %s",
			       username, XAS_GROUP, argv[1]);
			fprintf(stderr, "xas: %s is not allowed to use xas\n", username);
			return 1;
		}

		int authed = 0;
		for (int attempt = 0; attempt < MAX_ATTEMPTS && !authed; attempt++) {
			char password[PASS_MAX];
			if (read_password("[xas] password: ", password, sizeof password) != 0) {
				explicit_bzero(password, sizeof password);
				fprintf(stderr, "xas: failed to read password\n");
				return 1;
			}
			authed = (check_pass(username, password) == 0);
			explicit_bzero(password, sizeof password);

			if (!authed) {
				sleep(2);   /* замедление перебора */
				fprintf(stderr, "Sorry, try again.\n");
			}
		}
		if (!authed) {
			syslog(LOG_WARNING, "%s: authentication failure", username);
			return 1;
		}
	}

	syslog(LOG_NOTICE, "%s: running as root: %s", username, argv[1]);

	const char *term = getenv("TERM");
	if (clean_env(term) != 0) {
		perror("xas: environment");
		return 1;
	}

	if (become_root() != 0) {
		perror("xas: failed to become root");
		return 1;
	}

	execvp(argv[1], &argv[1]);
	perror(argv[1]);
	return 127;
}
