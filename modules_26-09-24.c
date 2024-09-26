#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define EXTERN_PORT 9078
#define HOME_PORT 9077
#define BUF_SIZE 2048
#define SHM_NAME "/shm_sip"
#define SHM_SIZE sizeof(SIP_Headers)

typedef struct
{
	char from[128];
	char to[128];
	char call_id[128];
	char via[256];
	char cseq[64];
	char contact[128];
	char content_length[32];
} SIP_Headers;

typedef struct
{
	char version[16];
	char owner_session_id[128];
	char session_name[128];
	char connection[128];
	char time[64];
	char media[256];
} SDP;

typedef struct
{
	int sockfd_extern;
	int sockfd_home;
	struct sockaddr_in client_addr_extern;
	struct sockaddr_in client_addr_home;
	SIP_Headers *shm_headers; // Shared memory
} Socket_Proxy;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void parse_headers(const char *message, SIP_Headers *headers);
void parse_SDP_section(const char *message, SDP *sdp);
void send_sip_message(int sockfd, struct sockaddr_in *client_addr, const char *method, SIP_Headers *headers, SDP *sdp);
void forward_sip_message(int sockfd, struct sockaddr_in *client_addr, const char *message);
void *handle_socket_extern(void *arg);
void *handle_socket_home(void *arg);
void cleanup(Socket_Proxy *proxy);

void *handle_socket_extern(void *arg)
{
	Socket_Proxy *proxy = (Socket_Proxy *)arg;
	char buffer[BUF_SIZE];
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);

	while (1)
	{
		int n = recvfrom(proxy->sockfd_extern, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&proxy->client_addr_extern, &addr_len);
		if (n < 0)
		{
			perror("recvfrom() extern");
			continue;
		}
		buffer[n] = '\0';

		pthread_mutex_lock(&lock);
		SIP_Headers headers;
		SDP sdp;
		parse_headers(buffer, proxy->shm_headers);
		parse_SDP_section(buffer, &sdp);
		printf("From: %s\n", proxy->shm_headers->from);
		printf("To: %s\n", proxy->shm_headers->to);
		pthread_mutex_unlock(&lock);
		if (strstr(buffer, "INVITE"))
		{
			forward_sip_message(proxy->sockfd_home, &proxy->client_addr_home, buffer);
			send_sip_message(proxy->sockfd_extern, &proxy->client_addr_extern, "100 Trying", &headers, &sdp);
		}
		else if (strstr(buffer, "ACK") || strstr(buffer, "BYE"))
		{
			forward_sip_message(proxy->sockfd_home, &proxy->client_addr_home, buffer);
		}
		pthread_mutex_unlock(&lock);
	}
	return NULL;
}

void *handle_socket_home(void *arg)
{
	Socket_Proxy *proxy = (Socket_Proxy *)arg;
	char buffer[BUF_SIZE];
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);

	while (1)
	{
		int n = recvfrom(proxy->sockfd_home, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&proxy->client_addr_home, &addr_len);
		if (n < 0)
		{
			perror("recvfrom() home");
			continue;
		}
		buffer[n] = '\0';

		pthread_mutex_lock(&lock);
		SIP_Headers headers;
		SDP sdp;
		parse_headers(buffer, proxy->shm_headers);
		parse_SDP_section(buffer, &sdp);

		// Write data to shared memory
		memcpy(proxy->shm_headers, &headers, sizeof(SIP_Headers));

		if (strstr(buffer, "100 Trying"))
		{
			printf("100 Trying from B\n");
		}
		else if (strstr(buffer, "180 Ringing"))
		{
			send_sip_message(proxy->sockfd_extern, &proxy->client_addr_extern, "180 Ringing", &headers, &sdp);
		}
		else if (strstr(buffer, "200 OK"))
		{
			send_sip_message(proxy->sockfd_extern, &proxy->client_addr_extern, "200 OK", &headers, &sdp);
		}
		pthread_mutex_unlock(&lock);
	}
	return NULL;
}

void parse_headers(const char *message, SIP_Headers *headers)
{
	const char *header_patterns[] = {"From:", "To:", "Call-ID:", "Via:", "CSeq:", "Contact:", "Content-Length:"};
	char *header_fields[] = {headers->from, headers->to, headers->call_id, headers->via, headers->cseq, headers->contact, headers->content_length};
	const int num_headers = sizeof(header_patterns) / sizeof(header_patterns[0]);

	for (int i = 0; i < num_headers; ++i)
	{
		const char *start = strstr(message, header_patterns[i]);
		if (start)
		{
			start += strlen(header_patterns[i]);
			while (*start == ' ')
				start++; // Skip any leading spaces
			const char *end = strstr(start, "\r\n");
			if (end)
			{
				size_t len = end - start;
				strncpy(header_fields[i], start, len);
				header_fields[i][len] = '\0';
			}
		}
	}
}

void parse_SDP_section(const char *message, SDP *sdp)
{
	const char *sdp_patterns[] = {"v=", "o=", "s=", "c=", "t=", "m="};
	char *sdp_fields[] = {sdp->version, sdp->owner_session_id, sdp->session_name, sdp->connection, sdp->time, sdp->media};
	const int num_sdp_fields = sizeof(sdp_patterns) / sizeof(sdp_patterns[0]);

	for (int i = 0; i < num_sdp_fields; ++i)
	{
		const char *start = strstr(message, sdp_patterns[i]);
		if (start)
		{
			start += strlen(sdp_patterns[i]);
			const char *end = strstr(start, "\r\n");
			if (end)
			{
				size_t len = end - start;
				strncpy(sdp_fields[i], start, len);
				sdp_fields[i][len] = '\0';
			}
		}
	}
}

void send_sip_message(int sockfd, struct sockaddr_in *client_addr, const char *method, SIP_Headers *headers, SDP *sdp)
{
	char response[BUF_SIZE];
	char sdp_message[BUF_SIZE];

	snprintf(response, sizeof(response),
			 "SIP/2.0 %s\r\n"
			 "Call-ID: %s\r\n"
			 "CSeq: %s\r\n"
			 "From: %s\r\n"
			 "To: %s\r\n"
			 "Via: %s\r\n"
			 "Contact: %s\r\n"
			 "Record-Route: <sip:%s:9078;lr>\r\n"
			 "Content-Length: %s\r\n",
			 method, headers->call_id, headers->cseq, headers->from, headers->to, headers->via, headers->contact, inet_ntoa(client_addr->sin_addr), headers->content_length);

	snprintf(sdp_message, sizeof(sdp_message),
			 "v=%s\r\n"
			 "o=%s\r\n"
			 "s=%s\r\n"
			 "c=%s\r\n"
			 "t=%s\r\n"
			 "m=%s\r\n",
			 sdp->version, sdp->owner_session_id, sdp->session_name, sdp->connection, sdp->time, sdp->media);

	if (strcmp(method, "401 Unauthorized") == 0)
	{
		strncat(response, "WWW-Authenticate: Digest realm=\"ss7demo.lab.cirpack.com\","
						  "nonce=\"00000acd29b0016738ed40e93cf545c6\","
						  "opaque=\"00000ac74f2d2ff\",stale=false,algorithm=MD5\r\n",
				sizeof(response) - strlen(response) - 1);
	}
	else if (strcmp(method, "180 Ringing") == 0 || (strcmp(method, "200 OK") == 0 && strstr(headers->cseq, "INVITE")))
	{
		strncat(response, sdp_message, sizeof(response) - strlen(response) - 1);
	}

	strncat(response, "\r\n", sizeof(response) - strlen(response) - 1);
	sendto(sockfd, response, strlen(response), 0, (struct sockaddr *)client_addr, sizeof(*client_addr));
	printf("Sent SIP response:\n%s\n", response);
}

void forward_sip_message(int sockfd, struct sockaddr_in *client_addr, const char *message)
{
	char modified_message[BUF_SIZE];
	char *request_line_end;

	request_line_end = strstr(message, "\r\n");
	if (!request_line_end)
	{
		printf("Invalid SIP message format\n");
		return;
	}

	size_t request_line_length = request_line_end - message + 2;
	strncpy(modified_message, message, request_line_length);
	modified_message[request_line_length] = '\0';

	char new_headers[400];
	snprintf(new_headers, sizeof(new_headers),
			 "Via: SIP/2.0/UDP 192.168.37.154:9078;branch=z9hG4bK-forward\r\n"
			 "Record-Route: <sip:192.168.37.154:9078;lr>\r\n");
	strncat(modified_message, new_headers, sizeof(modified_message) - strlen(modified_message) - 1);

	strncat(modified_message, request_line_end + 2, sizeof(modified_message) - strlen(modified_message) - 1);

	printf("SIP Request message:\n%s\n", message);
	printf("Modified message:\n%s\n", modified_message);

	if (sendto(sockfd, modified_message, strlen(modified_message), 0, (struct sockaddr *)client_addr, sizeof(*client_addr)) < 0)
	{
		perror("sendto() error");
	}
	else
	{
		printf("Forwarded modified message\n");
	}
}

void cleanup(Socket_Proxy *proxy)
{
	if (proxy->sockfd_extern >= 0)
	{
		close(proxy->sockfd_extern);
	}
	if (proxy->sockfd_home >= 0)
	{
		close(proxy->sockfd_home);
	}
	if (proxy->shm_headers != NULL)
	{
		munmap(proxy->shm_headers, SHM_SIZE);
		shm_unlink(SHM_NAME);
	}
}

int main(int argc, char *argv[])
{
	struct sockaddr_in serv_addr_extern, serv_addr_home;
	pthread_t extern_thread, home_thread;
	Socket_Proxy socket_proxy;

	socket_proxy.sockfd_extern = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_proxy.sockfd_extern < 0)
	{
		perror("socket() extern");
		exit(EXIT_FAILURE);
	}

	memset(&serv_addr_extern, 0, sizeof(serv_addr_extern));
	serv_addr_extern.sin_family = AF_INET;
	serv_addr_extern.sin_addr.s_addr = INADDR_ANY;
	serv_addr_extern.sin_port = htons(EXTERN_PORT);

	if (bind(socket_proxy.sockfd_extern, (struct sockaddr *)&serv_addr_extern, sizeof(serv_addr_extern)) < 0)
	{
		perror("bind() extern");
		cleanup(&socket_proxy);
		exit(EXIT_FAILURE);
	}

	socket_proxy.sockfd_home = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_proxy.sockfd_home < 0)
	{
		perror("socket() home");
		cleanup(&socket_proxy);
		exit(EXIT_FAILURE);
	}

	memset(&serv_addr_home, 0, sizeof(serv_addr_home));
	serv_addr_home.sin_family = AF_INET;
	serv_addr_home.sin_addr.s_addr = INADDR_ANY;
	serv_addr_home.sin_port = htons(HOME_PORT);

	if (bind(socket_proxy.sockfd_home, (struct sockaddr *)&serv_addr_home, sizeof(serv_addr_home)) < 0)
	{
		perror("bind() home");
		cleanup(&socket_proxy);
		exit(EXIT_FAILURE);
	}

	// Shared memory
	// Initialize shared memory
	int shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
	if (shm_fd == -1)
	{
		perror("shm_open");
		cleanup(&socket_proxy);
		exit(EXIT_FAILURE);
	}

	if (ftruncate(shm_fd, SHM_SIZE) == -1)
	{
		perror("ftruncate");
		close(shm_fd);
		cleanup(&socket_proxy);
		exit(EXIT_FAILURE);
	}

	socket_proxy.shm_headers = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
	if (socket_proxy.shm_headers == MAP_FAILED)
	{
		perror("mmap");
		close(shm_fd);
		cleanup(&socket_proxy);
		exit(EXIT_FAILURE);
	}
	close(shm_fd);

	memset(&socket_proxy.client_addr_home, 0, sizeof(socket_proxy.client_addr_home));
	socket_proxy.client_addr_home.sin_family = AF_INET;
	socket_proxy.client_addr_home.sin_port = htons(1111);
	if (inet_pton(AF_INET, "192.168.37.154", &(socket_proxy.client_addr_home.sin_addr)) <= 0)
	{
		perror("inet_pton() client_addr_home");
		cleanup(&socket_proxy);
		exit(EXIT_FAILURE);
	}

	if (pthread_create(&extern_thread, NULL, handle_socket_extern, (void *)&socket_proxy) != 0)
	{
		perror("pthread_create() extern_thread");
		cleanup(&socket_proxy);
		exit(EXIT_FAILURE);
	}

	if (pthread_create(&home_thread, NULL, handle_socket_home, (void *)&socket_proxy) != 0)
	{
		perror("pthread_create() home_thread");
		pthread_cancel(extern_thread);
		cleanup(&socket_proxy);
		exit(EXIT_FAILURE);
	}

	pthread_join(extern_thread, NULL);
	pthread_join(home_thread, NULL);

	pthread_mutex_destroy(&lock);
	cleanup(&socket_proxy);

	return 0;
}
