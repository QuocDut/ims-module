#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/shm.h>

#define PORT 5060
#define BUFFER_SIZE 1024
#define SHM_KEY 12345

void handle_sip_message(char *message);
void send_sip_message(const char *message, const char *dest_ip, int dest_port);
void parse_sdp(const char *sdp);
void store_register_info(const char *info);

int main()
{
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(client_addr);

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind socket to IP and port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("192.168.37.154");
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Listening for SIP messages on 192.168.37.154:%d\n", PORT);

    // Receive SIP messages
    while (1)
    {
        int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
        buffer[n] = '\0';
        printf("Received SIP message:\n%s\n", buffer);
        handle_sip_message(buffer);
    }

    close(sockfd);
    return 0;
}

void handle_sip_message(char *message)
{
    // Parse headers and validate
    // For simplicity, just print the message
    printf("Handling SIP message:\n%s\n", message);

    // Extract SDP section and parse media information
    char *sdp = strstr(message, "\r\n\r\n");
    if (sdp)
    {
        sdp += 4; // Skip the \r\n\r\n
        parse_sdp(sdp);
    }
}

void send_sip_message(const char *message, const char *dest_ip, int dest_port)
{
    int sockfd;
    struct sockaddr_in dest_addr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Socket creation failed");
        return;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip);
    dest_addr.sin_port = htons(dest_port);

    sendto(sockfd, message, strlen(message), 0, (const struct sockaddr *)&dest_addr, sizeof(dest_addr));
    close(sockfd);
}

void parse_sdp(const char *sdp)
{
    // Parse SDP for media information
    printf("Parsing SDP:\n%s\n", sdp);
}

void store_register_info(const char *info)
{
    int shmid;
    char *shmaddr;

    if ((shmid = shmget(SHM_KEY, BUFFER_SIZE, IPC_CREAT | 0666)) < 0)
    {
        perror("shmget failed");
        return;
    }

    if ((shmaddr = shmat(shmid, NULL, 0)) == (char *)-1)
    {
        perror("shmat failed");
        return;
    }

    strncpy(shmaddr, info, BUFFER_SIZE);
    shmdt(shmaddr);
}