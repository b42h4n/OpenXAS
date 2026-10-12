# OpenXAS

### A minimal sudo/doas alternative for Linux.

<p align="center">
  <strong>Authenticate. Execute. Get things done.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Linux-informational?style=flat-square&logo=linux&logoColor=white" alt="Linux" />
  <img src="https://img.shields.io/badge/language-C-A8B9CC?style=flat-square&logo=c&logoColor=white" alt="C" />
  <img src="https://img.shields.io/badge/license-AGPL-lightgrey?style=flat-square" alt="License AGPL" />
</p>

---

> [!WARNING]
> This is experimental software, primarily built with AI.

## Overview

**xas** is a minimal command-line utility written in C that just works, whose main purpose is execute a command with root privileges.

No complex configuration. No unnecessary dependencies beyond the system libraries. Just a small utility built around traditional Linux interfaces.

## Features

- **Password authentication** — verifies a supplied password using the system's password hash.
- **Shadow password support** — retrieves password information through the shadow password API.
- **Command execution** — accepts a command and its arguments from the command line.
- **Minimal implementation** — written in C using standard and POSIX-related system interfaces.
- **Terminal password prompt** — uses `getpass()` to request the password without ordinary terminal echo.

## How it works

The execution flow is straightforward:

```text
User
 │
 ▼
xas <command>
 │
 ▼
Read login name
 │
 ▼
Request password
 │
 ▼
Verify password hash
 │
 ├── Authentication failed ──► Exit
 │
 ▼
Attempt setuid(0)
 │
 ├── Failed ──────────────────► Exit
 │
 ▼
Execute command
```

## Requirements

Before building `xas`, make sure you have:

- A Linux system with a C compiler.
- Development headers for the C library.
- Shadow password API headers.
- `libcrypt` development files.
- Appropriate system privileges and configuration for accessing shadow password information and changing user IDs.

## Building

Clone the repository:

```sh
git clone https://github.com/b42h4n/OpenXAS
cd OpenXAS
```

Compile the source:

```sh
gcc -Wall -Wextra -O2 xas.c -o xas -lcrypt
```

If you want use musl libc do this:

```sh
musl-gcc -Wall -Wextra -O2 xas.c -o xas -lcrypt
```

And giving SUID privileges:

```sh
sudo chown root:root ./xas
sudo chmod 4755 ./xas
```

Optional: adding xas to PATH:

```sh
sudo/doas mv ./xas /usr/local/bin
```

## Usage

```sh
xas <command> [arguments...]
```

For example:

```sh
xas apt update
xas apt install musl-tools
```

The program requests a password before proceeding.

**Note:** These examples illustrate command-line syntax only. Successful execution depends on the program's privileges, the system configuration, and the authentication implementation.

Important considerations:

- Access to `/etc/shadow` is restricted on typical Linux systems.
- Calling `setuid(0)` does not automatically grant root privileges; the process must already have the required privilege.
- `system()` invokes a command interpreter, which introduces shell parsing and injection risks.
- Command construction must enforce buffer boundaries.
- Password buffers must be initialized, validated, and handled carefully.
- Login-name retrieval and password-prompt failures must terminate execution safely.
- A privileged authentication utility needs careful review of environment handling, process credentials, and failure paths.

**Do not install `xas` as a setuid-root executable on a production system in its current form.** The implementation requires additional security review and hardening before privileged deployment.

## Project status

`xas` is a minimal C experiment exploring Linux authentication interfaces and privileged command execution.

The project prioritizes a small codebase and a straightforward execution flow.

## Known issues
Due to certain errors, the code cannot be compiled for musl libc.
There is no authentication cache, so it asks for the password again every time. It’s inconvenient, but secure.

## Contributing

Suggestions, bug reports, and improvements are welcome. Security-related issues should be reported responsibly.

## License

Affero GNU General public license.

---

<p align="center">
  <sub>Built with C and a Unix mindset.</sub>
</p>
