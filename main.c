# define _XOPEN_SOURCE
# define _DEFAULT_SOURCE

# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <limits.h>
# include <string.h>
# include <shadow.h>
# include <crypt.h>

int check_pass(const char *username, const char *password)
{
	if (!username || !password) return 1;

	struct spwd *sp = getspnam(username);
	if (sp == NULL)
	{
		return 1;
	}
	
	char *hashed = crypt(password, sp->sp_pwdp);
	if (hashed == NULL)
	{
		return 1;
	}	

	if (strcmp(hashed, sp->sp_pwdp) == 0)
	{
		return 0;
	}
	
	return 1;
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		printf("Usage: xas <command>\n");
		return 1;
	}
	char cmd[4096] = "";
	
	for (int i = 1; i < argc; ++i)
	{
		strcat(cmd, argv[i]);
		if (i < argc - 1)
		{
			strcat(cmd, " ");
		}
	}

	char username[LOGIN_NAME_MAX];
	char password[256];

	if (getlogin_r(username, sizeof(username)) == 0)
	{
		char *input = getpass("[xas] password: ");
		if (input != NULL)
		{
			strncpy(password, input, sizeof(password) - 1);
		}
	} else
	{
		perror("User error!");
	}

	if (check_pass(username, password) == 0)
	{
		if (setuid(0) != 0)
		{
			perror("Failed to setuid");
			return 1;
		}
		system(cmd);
	} else
	{
		perror("Error");
		return 1;
	}

	return 0;
}
