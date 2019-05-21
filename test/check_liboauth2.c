/***************************************************************************
 *
 * Copyright (C) 2018-2019 - ZmartZone Holding BV - www.zmartzone.eu
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 **************************************************************************/

#include "check_liboauth2.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../include/oauth2/log.h"
#include "../include/oauth2/mem.h"
//#include <semaphore.h>

static int http_server_port = 8888;
static int http_server_signal_delivered = 0;

#define HTTP_SERVER_BUFSIZE 8096

#define HTTP_SERVER_SIGNUM SIGCONT

static void http_server_signal_handler(int signum)
{
	http_server_signal_delivered = signum;
}

static void http_server_error(oauth2_log_t *log, int type, int socket_fd)
{
	ssize_t rc;
	static char buf[HTTP_SERVER_BUFSIZE + 1];
	char *status = "500 Internal Server Error";

	if (type == 400)
		status = "400 Bad Request";
	else if (type == 403)
		status = "403 Forbidden";
	else if (type == 404)
		status = "404 Not Found";
	else if (type == 405)
		status = "405 Method Not Allowed";
	else if (type == 406)
		status = "406 Not Acceptable";

	sprintf(buf, "HTTP/1.1 %s\nContent-Length: 0\nConnection: close\n\n",
		status);

	rc = write(socket_fd, buf, strlen(buf));
	(void)rc;
}

struct {
	char *ext;
	char *filetype;
} extensions[] = {{"html", "text/html"}, {"json", "application/json"}, {0, 0}};

typedef char *(http_serve_callback_t)(const char *);

struct {
	char *path;
	http_serve_callback_t *callback;
} http_serve_routing[] = {{"check_http", oauth2_check_http_serve},
			  {"check_jose", oauth2_check_jose_serve},
			  {"check_oauth2", oauth2_check_oauth2_serve},
			  {0, 0}};

static void http_server_process(oauth2_log_t *log, int fd, int hit)
{
	int j, file_fd, buflen;
	long i, ret, len;
	char *fstr;
	static char buffer[HTTP_SERVER_BUFSIZE + 1];
	static char outbuf[HTTP_SERVER_BUFSIZE + 1];
	ssize_t rc;
	char *response = NULL;

	ret = read(fd, buffer, HTTP_SERVER_BUFSIZE);
	if (ret == 0 || ret == -1) {
		http_server_error(log, 400, fd);
		return;
	}
	if (ret > 0 && ret < HTTP_SERVER_BUFSIZE)
		buffer[ret] = 0;
	else
		buffer[0] = 0;
	for (i = 0; i < ret; i++)
		if (buffer[i] == '\r' || buffer[i] == '\n')
			buffer[i] = '*';
	oauth2_debug(log, "request: %s %d", buffer, hit);
	/*
	if (strncmp(buffer, "GET ", 4) && strncmp(buffer, "get ", 4)) {
		http_server_error(log, 405, fd);
		return;
	}
	*/
	for (i = 4; i < HTTP_SERVER_BUFSIZE; i++) {
		if (buffer[i] == ' ') {
			buffer[i] = 0;
			break;
		}
	}
	for (j = 0; j < i - 1; j++)
		if (buffer[j] == '.' && buffer[j + 1] == '.') {
			http_server_error(log, 403, fd);
			return;
		}

	if (!strncmp(&buffer[0], "GET /\0", 6) ||
	    !strncmp(&buffer[0], "get /\0", 6))
		(void)strcpy(buffer, "GET /index.html");

	buflen = strlen(buffer);
	fstr = (char *)0;
	for (i = 0; extensions[i].ext != 0; i++) {
		len = strlen(extensions[i].ext);
		if (!strncmp(&buffer[buflen - len], extensions[i].ext, len)) {
			fstr = extensions[i].filetype;
			break;
		}
	}

	if (fstr == 0) {
		// http_server_error(log, 406, fd);
		// return;
		fstr = "application/json";
	}

	for (i = 0; http_serve_routing[i].path != 0; i++) {
		len = strlen(http_serve_routing[i].path);
		if ((strncmp(&buffer[5], http_serve_routing[i].path, len) ==
		     0) ||
		    (strncmp(&buffer[6], http_serve_routing[i].path, len) ==
		     0)) {
			// TOOD: split headers and body
			response = http_serve_routing[i].callback(buffer);
			sprintf(outbuf,
				"HTTP/1.1 200\nContent-Length: "
				"%lu\nConnection: close\n\n",
				strlen(response));
			rc = write(fd, outbuf, strlen(outbuf));
			rc = write(fd, response, strlen(response));
			(void)rc;
			oauth2_mem_free(response);
			return;
		}
	}

	if ((file_fd = open(&buffer[5], O_RDONLY)) == -1) {
		http_server_error(log, 404, fd);
		return;
	}
	oauth2_debug(log, "SEND: %s, %d", &buffer[5], hit);
	len = (long)lseek(file_fd, (off_t)0, SEEK_END);
	(void)lseek(file_fd, (off_t)0, SEEK_SET);
	(void)sprintf(buffer,
		      "HTTP/1.1 200 OK\nServer: "
		      "libmodauth2/1.0\nContent-Length: "
		      "%ld\nConnection: close\nContent-Type: %s\n\n",
		      len, fstr);
	oauth2_debug(log, "Header: %s, %d", buffer, hit);
	rc = write(fd, buffer, strlen(buffer));
	(void)rc;

	while ((ret = read(file_fd, buffer, HTTP_SERVER_BUFSIZE)) > 0) {
		rc = write(fd, buffer, ret);
		(void)rc;
	}
}

// static sem_t *sema = NULL;

pid_t http_server_spawn()
{

	int listenfd, socketfd, hit;
	static struct sockaddr_in serv_addr;
	static struct sockaddr_in cli_addr;
	fd_set read_fd_set;
	socklen_t length;

	pid_t pid = fork();
	if (pid != 0) {
		return pid;
	}

	struct sigaction action;
	action.sa_flags = 0;
	action.sa_handler = http_server_signal_handler;
	sigemptyset(&action.sa_mask);
	sigaction(HTTP_SERVER_SIGNUM, &action, NULL);

	oauth2_log_t *log = oauth2_log_init(OAUTH2_LOG_TRACE1, NULL);

	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		oauth2_error(log, "socket failed");
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(http_server_port);
	if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) <
	    0)
		oauth2_error(log, "bind failed");
	if (listen(listenfd, 64) < 0)
		oauth2_error(log, "listen failed");

	FD_ZERO(&read_fd_set);
	FD_SET(listenfd, &read_fd_set);

	// sem_post(sema);

	for (hit = 1;; hit++) {

		if (select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0) {
			if (http_server_signal_delivered == HTTP_SERVER_SIGNUM)
				break;
			oauth2_error(log, "select failed: %s", strerror(errno));
		}

		if (FD_ISSET(listenfd, &read_fd_set)) {

			length = sizeof(cli_addr);
			if ((socketfd =
				 accept(listenfd, (struct sockaddr *)&cli_addr,
					&length)) <= 0) {
				oauth2_error(log, "accept failed: %s, %d",
					     strerror(errno), socketfd);
				continue;
			}

			if (fork() == 0) {

				http_server_process(log, socketfd, hit);

				close(socketfd);
				oauth2_log_free(log);

				exit(0);
			}
		}
	}

	close(listenfd);
	oauth2_log_free(log);

	exit(0);
}

int main(void)
{
	int n_failed;

	// sema = sem_open ("sema", O_CREAT | O_EXCL, 0644, 0);
	pid_t pid = http_server_spawn();
	// sleep(1);
	// sem_wait(sema);

	SRunner *sr = srunner_create(suite_create("liboauth2"));

	// srunner_set_fork_status(sr, CK_NOFORK);

	srunner_add_suite(sr, oauth2_check_version_suite());
	srunner_add_suite(sr, oauth2_check_mem_suite());
	srunner_add_suite(sr, oauth2_check_log_suite());
	srunner_add_suite(sr, oauth2_check_util_suite());
	srunner_add_suite(sr, oauth2_check_ipc_suite());
	srunner_add_suite(sr, oauth2_check_cache_suite());
	srunner_add_suite(sr, oauth2_check_jose_suite());
	srunner_add_suite(sr, oauth2_check_http_suite());
	srunner_add_suite(sr, oauth2_check_proto_suite());
	srunner_add_suite(sr, oauth2_check_oauth2_suite());
	srunner_add_suite(sr, oauth2_check_openidc_suite());
	srunner_add_suite(sr, oauth2_check_apache_suite());

	// srunner_run_all(sr, CK_ENV);
	srunner_run_all(sr, CK_VERBOSE);
	n_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	kill(pid, HTTP_SERVER_SIGNUM);
	waitpid(pid, NULL, 0);

	// sem_unlink("sema");

	return (n_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
