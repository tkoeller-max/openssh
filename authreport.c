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

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "config.h"
#include "packet.h"
#include "log.h"
#include "misc.h"
#include "auth.h"
#include "authreport.h"

static int sock_l = -1;

void
init_auth_report(const char *skt_path)
{
	static const size_t sbsize = 1024;

	struct sockaddr_un remaddr = {
		.sun_family = AF_UNIX,
		.sun_path = { 0 }
	};

	if (skt_path == NULL || *skt_path == 0 ||
	    strcasecmp(skt_path, "none") == 0) {
		verbose("Authresult processing disabled");
		return;
	}

	strncpy(remaddr.sun_path, skt_path, sizeof remaddr.sun_path);
	if (*(remaddr.sun_path + sizeof remaddr.sun_path - 1) != 0) {
		/* Error: socket path truncated */
		fatal_f("Path '%s' too long", skt_path);
	}

	sock_l = socket(PF_LOCAL, SOCK_DGRAM, 0);

	if (sock_l == -1) {
		/* Error: failed to create local socket */
		fatal_f("Failed to create local socket %s: %s",
			skt_path, strerror(errno));
	}

	if (setsockopt(sock_l, SOL_SOCKET, SO_SNDBUF, &sbsize,  sizeof sbsize) < 0) {
		fatal_f("Failed to set socket buffer size:%s",
			strerror(errno));
	}

	if (set_nonblock(sock_l) < 0) {
		fatal_f("Failed to set socket nonblocking mode");
	}

	if (connect(sock_l, (__CONST_SOCKADDR_ARG) &remaddr, SUN_LEN(&remaddr)) < 0) {
		fatal_f("Failed to connect to socket %s: %s",
		skt_path, strerror(errno));
	}
}

void
report_auth_result(struct ssh *ssh)
{
	char rec[100];
	int n;
	const Authctxt *authctxt = ssh->authctxt;
	ssize_t nout;

	if (sock_l == -1) return;

	n = snprintf(rec, sizeof rec, AUTHRPT_REC_FMT,
		     authctxt->valid ? AUTHRPT_RES_ACCEPT : AUTHRPT_RES_REJECT,
		     ssh_remote_ipaddr(ssh),
		     ssh_remote_port(ssh),
		     authctxt->user
	);

	if (n >= sizeof rec) {
		error_f("Record length %d exceeds buffer size %z",
			n, sizeof rec);
		return;
	}

	nout = write(sock_l, rec, (size_t) n);
	if (nout != n) {
		if (nout < 0)
			error_f("Communication failure:%s", strerror(errno));
		else
			error_f("Message tuncated");
		/* Is there a better way to handle this condition? */
		close(sock_l);
		sock_l = -1;
	}
}
