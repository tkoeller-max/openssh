
/*
 * Copyright (c) 2022 Thomas Koeller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>

static const struct sockaddr_un sa = {
	.sun_family = AF_UNIX,
	.sun_path = "/tmp/authreport-test"
};

static void
cleanup(void)
{
	unlink(sa.sun_path);
}

static void
sh(int)
{
	cleanup();
};

int
main(void)
{
	char inbuf[100];

	static const struct sigaction sact = {
		.sa_handler = sh
	};

	const int s = socket(sa.sun_family, SOCK_DGRAM, 0);
	if (s < 0) {
		error(1, errno, "Socket creation failed");
	}

	if (bind(s, (const struct sockaddr *) &sa, SUN_LEN(&sa)) < 0) {
		error(1, errno, "Failed to bind socket address %s", sa.sun_path);
	}
	atexit(cleanup);
	sigaction(SIGINT, &sact, NULL);

	while (recv(s, inbuf, sizeof inbuf, 0) > 0) {
		puts(inbuf);
		memset(inbuf, 0, sizeof inbuf);
	}

	exit(0);
}

