/**
 * @Proxy Call Session Control Function
 * @file modules.c
 * @brief This module provides functionalities for managing and interacting with various IMS (Inventory Management System) components.
 *
 * This module includes functions for adding, removing, and updating inventory items, as well as querying inventory status and generating reports.
 *
 * Detailed description of the module, including its purpose, usage, and any important notes.
 * Purpose: To facilitate inventory management operations within the IMS. * - Usage: Include this module in your project to access inventory management functions.
 * Important Notes: Ensure that the database connection is properly configured before using this module.
 **/
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#define SHM_NAME "/Registered_info"

#define EXTERN_PORT 9078
#define HOME_PORT 9077
#define BUF_SIZE 2048

typedef struct
{
    char phone_number[100][21]; // 20 characters + null terminator
    char user_name[100][21];    // 20 characters + null terminator
    char ip[100][101];          // 100 characters + null terminator
    char port[100][6];          // 5 characters + null terminator
    int index;
} User_Memory;

typedef struct
{
    char from[100];          // From header is usually a single line
    char to[100];            // To header is usually a single line
    char call_id[100];       // Call ID is usually a single line
    char via[100];           // Via header is usually a single line
    char cseq[20];           // CSeq is usually a single line
    char contact[100];       // Contact header is usually a single line
    char content_length[10]; // Content length is usually a single line
} SIP_Headers;

typedef struct
{
    char version[10];          // SDP version is usually a single digit
    char owner_session_id[50]; // Owner and session ID can be a bit longer
    char session_name[50];     // Session name is typically short
    char connection[50];       // Connection information
    char time[20];             // Time information
    char media[50];            // Media description
} SDP;

typedef struct
{
    int sockfd_extern;                     // Socket file descriptor for external communication
    int sockfd_home;                       // Socket file descriptor for home communication
    struct sockaddr_in client_addr_extern; // Client address for external communication
    struct sockaddr_in client_addr_home;   // Client address for home communication
} Socket_Proxy;

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
User_Memory *shm = NULL;
void parse_headers(const char *message, SIP_Headers *headers);
void parse_SDP_section(const char *message, SDP *sdp);
void register_user(const char *message, User_Memory *shm);
User_Memory *init_shared_memory();
void read_register_user(User_Memory *shm);
void send_sip_message(int sockfd, struct sockaddr_in *client_addr, char *method, SIP_Headers *headers, SDP *sdp);
void forward_sip_message(int sockfd, char *ip, int port, const char *message);
void *handle_socket_extern(void *arg);
void *handle_socket_home(void *arg);
void get_receiver_info(const char *message, char *user_name, char *phone_number);
int find_registered_User(char *user_name, char *phone_number, User_Memory *shm);

User_Memory *init_shared_memory() // Function to initialize the shared memory
{
    int shm_fd;
    int created = 0;
    User_Memory *shm;
    shm_fd = shm_open(SHM_NAME, O_RDWR, 0);
    if (shm_fd == -1)
    {
        shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
        printf("Init\n");
        if (shm_fd == -1)
        {
            perror("shm_open()");
            return NULL;
        }
        created = 1; // Flag to indicate that the shared memory was created
    }
    else
    {
        printf("Open\n"); // Flag to indicate that the shared memory was opened
    }
    if (created)
    {
        if (ftruncate(shm_fd, sizeof(User_Memory)) == -1)
        {
            perror("ftruncate");
            close(shm_fd);
            shm_unlink(SHM_NAME);
            return NULL;
        }
    }
    shm = mmap(NULL, sizeof(User_Memory), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0); // Map the shared memory
    if (shm == MAP_FAILED)
    {
        perror("mmap failed");
        close(shm_fd);
        if (created)
        {
            shm_unlink(SHM_NAME);
        }
        return NULL;
    }
    if (created)
    {
        memset(shm, 0, sizeof(User_Memory));
    }

    close(shm_fd);
    return shm;
}

void signal_handler(int signum)
{
    if (signum == SIGINT)
    {
        printf("Received SIGINT. Cleaning up and exiting...\n");
        if (shm != NULL)
        {
            munmap(shm, sizeof(User_Memory));
            shm = NULL;
        }
        exit(0);
    }
}

void *handle_socket_extern(void *arg) // Function to handle the external socket
{
    Socket_Proxy *socket_proxy = (Socket_Proxy *)arg;
    int len_extern = sizeof(struct sockaddr_in);
    char extern_buffer[BUF_SIZE];
    SIP_Headers extern_headers;
    SDP extern_sdp;
    int n;
    int register_count = 0;
    int registered_user_index;
    char phone_number[20];
    char user_name[20];
    char registered_ip[20];
    int registered_port;
    while (1)
    {
        printf("Waiting for message on EXTERN socket\n");
        n = recvfrom(socket_proxy->sockfd_extern, extern_buffer, sizeof(extern_buffer), 0, (struct sockaddr *)&socket_proxy->client_addr_extern, &len_extern);
        extern_buffer[n] = '\0';
        pthread_mutex_lock(&lock);
        // print received message
        printf("Received from Caller to extern: \n%s\n", extern_buffer);
        parse_headers(extern_buffer, &extern_headers);
        // parse sdp if available
        if (strstr(extern_buffer, "REGISTER") && register_count == 0)
        {
            strcpy(registered_ip, "192.168.37.154");
            registered_port = 2028;
            forward_sip_message(socket_proxy->sockfd_home, registered_ip, registered_port, extern_buffer);
            send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "100 Trying", &extern_headers, NULL);
            register_count++;
        }
        // REGISTER
        else if (strstr(extern_buffer, "REGISTER") && register_count == 1)
        {
            register_user(extern_buffer, shm);
            read_register_user(shm);
            forward_sip_message(socket_proxy->sockfd_home, registered_ip, registered_port, extern_buffer);
            send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "100 Trying", &extern_headers, NULL);
            register_count--;
        }
        // INVITE
        else if (strstr(extern_buffer, "INVITE"))
        {
            // check To headers: user_name && phone_number in extern_headers coincided with shm->user_name && shm->phone_number
            get_receiver_info(extern_buffer, user_name, phone_number);
            printf("Receiver User\n");
            printf("Phone Number: %s\n", phone_number);
            printf("User Name: %s\n", user_name);
            printf("Index: %d\n", shm->index);
            printf("Phone Number: %s\n", shm->phone_number);
            printf("User Name: %s\n", shm->user_name);
            registered_user_index = find_registered_User(user_name, phone_number, shm);
            // true:
            if (registered_user_index >= 0)
            {
                printf("User is registered\n");
                strncpy(registered_ip, shm->ip[registered_user_index], sizeof(registered_ip) - 1);
                registered_ip[sizeof(registered_ip) - 1] = '\0';
                char *registered_port_str = shm->port[registered_user_index];
                // char to int
                registered_port = atoi(registered_port_str);
                forward_sip_message(socket_proxy->sockfd_home, registered_ip, registered_port, extern_buffer);
                send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "100 Trying", &extern_headers, &extern_sdp);
            }
            else // false
            {
                send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "404 Not Found", &extern_headers, NULL);
                exit(0);
            }
        }
        // ACK
        else if (strstr(extern_buffer, "ACK"))
        {
            forward_sip_message(socket_proxy->sockfd_home, registered_ip, registered_port, extern_buffer);
        }
        // BYE
        else if (strstr(extern_buffer, "BYE"))
        {
            forward_sip_message(socket_proxy->sockfd_home, registered_ip, registered_port, extern_buffer);
        }
        pthread_mutex_unlock(&lock);
    }
}

void *handle_socket_home(void *arg)
{ // Function to handle the home socket
    Socket_Proxy *socket_proxy = (Socket_Proxy *)arg;
    int len_home = sizeof(struct sockaddr_in);
    char home_buffer[BUF_SIZE];
    SIP_Headers home_headers;
    SDP home_sdp;
    int m;
    while (1)
    {
        m = recvfrom(socket_proxy->sockfd_home, home_buffer, sizeof(home_buffer), 0, (struct sockaddr *)&socket_proxy->client_addr_home, &len_home);
        home_buffer[m] = '\0';
        printf("Received from User to Home:\n%s\n", home_buffer);
        pthread_mutex_lock(&lock);
        parse_headers(home_buffer, &home_headers);
        parse_SDP_section(home_buffer, &home_sdp);
        // 100 Trying
        if (strstr(home_buffer, "100 Trying"))
        {
            printf("100 Trying from B\n");
        }
        // 401 Unauthorized
        else if (strstr(home_buffer, "401 Unauthorized"))
        {
            send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "401 Unauthorized", &home_headers, NULL);
        }
        // 180 Ringing
        else if (strstr(home_buffer, "180 Ringing"))
        {
            send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "180 Ringing", &home_headers, &home_sdp);
        } // 404 Not Found
        else if (strstr(home_buffer, "404 Not Found"))
        {
            send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "404 Not Found", &home_headers, NULL);
        }
        // 200 OK
        else if (strstr(home_buffer, "200 OK"))
        {
            send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "200 OK", &home_headers, &home_sdp);
        }
        pthread_mutex_unlock(&lock);
    }
}

void parse_headers(const char *message, SIP_Headers *headers)
{ // Function to parse the SIP headers
    char message_copy[BUF_SIZE];
    strncpy(message_copy, message, BUF_SIZE - 1);
    message_copy[BUF_SIZE - 1] = '\0';

    char *line = strtok(message_copy, "\r\n");
    while (line != NULL)
    {
        if (strncmp(line, "To:", 3) == 0)
        {
            printf("Found To header --> %s\n", line);
            strncpy(headers->to, line + 4, 99);
            headers->to[99] = '\0';
        }
        else if (strncmp(line, "From:", 5) == 0)
        {
            printf("Found header --> %s\n", line);
            strncpy(headers->from, line + 6, 99);
            headers->from[99] = '\0';
        }
        else if (strncmp(line, "Via:", 4) == 0)
        {
            printf("Found header --> %s\n", line);
            strncpy(headers->via, line + 5, 99);
            headers->via[99] = '\0';
        }
        else if (strncmp(line, "Call-ID:", 8) == 0)
        {
            printf("Found header --> %s\n", line);
            strncpy(headers->call_id, line + 9, 99);
            headers->call_id[99] = '\0';
        }
        else if (strncmp(line, "CSeq:", 5) == 0)
        {
            printf("Found header --> %s\n", line);
            strncpy(headers->cseq, line + 6, 99);
            headers->cseq[99] = '\0';
        }
        else if (strncmp(line, "Contact:", 8) == 0)
        {
            printf("Found header --> %s\n", line);
            strncpy(headers->contact, line + 9, 99);
            headers->contact[99] = '\0';
        }
        else if (strncmp(line, "Content-Length:", 15) == 0)
        {
            printf("Found header --> %s\n", line);
            strncpy(headers->content_length, line + 16, 99);
            headers->content_length[99] = '\0';
        }
        line = strtok(NULL, "\r\n");
    }
}

void parse_SDP_section(const char *message, SDP *sdp) // Function to parse the SDP section
{
    char message_copy[BUF_SIZE];
    strncpy(message_copy, message, BUF_SIZE - 1);
    message_copy[BUF_SIZE - 1] = '\0';
    // Split the message by line
    char *line = strtok(message_copy, "\r\n");
    while (line != NULL)
    {
        if (strncmp(line, "v=", 2) == 0)
        {
            printf("Found version Protocol: %s\n", line);
            strncpy(sdp->version, line + 2, 99);
            sdp->version[99] = '\0';
        }
        else if (strncmp(line, "o=", 2) == 0)
        {
            printf("Found owner and session Id: %s\n", line);
            strncpy(sdp->owner_session_id, line + 2, 99);
            sdp->owner_session_id[99] = '\0';
        }
        else if (strncmp(line, "s=", 2) == 0)
        {
            printf("Found session Name: %s\n", line);
            strncpy(sdp->session_name, line + 2, 99);
            sdp->session_name[99] = '\0';
        }

        else if (strncmp(line, "c=", 2) == 0)
        {

            printf("Found connection Information: %s\n", line);
            strncpy(sdp->connection, line + 2, 99);
            sdp->connection[99] = '\0';
        }
        else if (strncmp(line, "t=", 2) == 0)
        {
            printf("Found session Time : %s\n", line);
            strncpy(sdp->time, line + 2, 99);
            sdp->time[99] = '\0';
        }
        else if (strncmp(line, "m=", 2) == 0)
        {
            printf("Found media : %s\n", line);
            strncpy(sdp->media, line + 2, 99);
            sdp->media[99] = '\0';
        }
        line = strtok(NULL, "\r\n");
    }
}

void send_sip_message(int sockfd, struct sockaddr_in *client_addr, char *method, SIP_Headers *headers, SDP *sdp)
{ // Function to send a SIP message
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
    if (sdp != NULL)
    {
        snprintf(sdp_message, sizeof(sdp_message),
                 "v=%s\r\n"
                 "o=%s\r\n"
                 "s=%s\r\n"
                 "c=%s\r\n"
                 "t=%s\r\n"
                 "m=%s\r\n",
                 sdp->version, sdp->owner_session_id, sdp->session_name, sdp->connection, sdp->time, sdp->media);
        strncat(response, sdp_message, sizeof(response) - strlen(response) - 1);
    }
    if (strcmp(method, "401 Unauthorized") == 0)
    {
        strncat(response, "WWW-Authenticate: Digest realm=\"ss7demo.lab.cirpack.com\","
                          "nonce=\"00000acd29b0016738ed40e93cf545c6\","
                          "opaque=\"00000ac74f2d2ff\",stale=false,algorithm=MD5\r\n",
                sizeof(response) - strlen(response) - 1);
    }
    strncat(response, "\r\n", sizeof(response) - strlen(response) - 1);
    sendto(sockfd, response, strlen(response), 0, (struct sockaddr *)client_addr, sizeof(*client_addr));
    printf("Sent SIP response:\n%s\n", response);
}

void register_user(const char *message, User_Memory *shm) // Function to register a user
{
    const char *from = strstr(message, "From:");
    if (from)
    {
        const char *start = strstr(from, "sip:");
        if (start)
        {
            start += 4;
            const char *end = strchr(start, '@');
            if (end && (end - start < sizeof(shm->phone_number[shm->index])))
            {
                strncpy(shm->phone_number[shm->index], start, end - start);
                shm->phone_number[shm->index][end - start] = '\0';
            }
        }

        const char *name_start = strchr(from, ' ');
        const char *name_end = strstr(from, " <");
        if (name_start && name_end && name_start < name_end)
        {
            size_t name_length = name_end - name_start;
            if (name_length < sizeof(shm->user_name[shm->index]))
            {
                strncpy(shm->user_name[shm->index], name_start + 1, name_length - 1);
                shm->user_name[shm->index][name_length - 1] = '\0';
            }
        }
    }
    // Get IP and port
    const char *contact = strstr(message, "Contact:");
    if (contact)
    {
        const char *start = strstr(contact, "sip:");
        if (start)
        {
            start += 4;
            const char *end_ip = strchr(start, ':');
            const char *end_port = strchr(end_ip + 1, '>'); // Find the end of the port number

            if (end_ip && end_port && (end_ip - start < sizeof(shm->ip[shm->index])))
            {
                strncpy(shm->ip[shm->index], start, end_ip - start);
                shm->ip[shm->index][end_ip - start] = '\0';

                size_t port_len = end_port - (end_ip + 1);
                if (port_len > 0 && port_len < sizeof(shm->port[shm->index]))
                {
                    strncpy(shm->port[shm->index], end_ip + 1, port_len);
                    shm->port[shm->index][port_len] = '\0';
                }
            }
        }
    }
    shm->index++;
    if (shm->index >= 100)
    {
        shm->index = 0;
    }
}

void get_receiver_info(const char *message, char *user_name, char *phone_number) // Function to get the receiver information
{
    const char *to = strstr(message, "To:");
    if (to)
    {
        const char *start = strstr(to, "sip:");
        if (start)
        {
            start += 4; // Skip the "sip:"
            const char *end = strchr(start, '@');
            if (end && (end - start < 20))
            {
                strncpy(phone_number, start, end - start);
                phone_number[end - start] = '\0';
            }
        }

        const char *name_start = strchr(to, ' ');
        const char *name_end = strstr(to, " <");
        if (name_start && name_end && name_start < name_end)
        {
            size_t name_length = name_end - name_start;
            if (name_length < 20)
            {
                strncpy(user_name, name_start + 1, name_length - 1);
                user_name[name_length - 1] = '\0';
            }
        }
    }
}

void read_register_user(User_Memory *shm) // Function to read the registered users
{
    for (int i = 0; i < shm->index; i++)
    {
        printf("User %d registered:\n", i + 1);
        printf("Phone Number: %s\n", shm->phone_number[i]);
        printf("User Name: %s\n", shm->user_name[i]);
        printf("IP: %s\n", shm->ip[i]);
        printf("Port: %s\n", shm->port[i]);
        printf("\n");
    }
}
int find_registered_User(char *user_name, char *phone_number, User_Memory *shm) // Function to find a registered user
{
    for (int i = 0; i < shm->index; i++)
    {
        if (strcmp(user_name, shm->user_name[i]) == 0 && strcmp(phone_number, shm->phone_number[i]) == 0)
        {
            return i;
        }
    }
    return -1;
}

void forward_sip_message(int sockfd, char *ip, int port, const char *message)
{ // Function to forward a SIP message
    char modified_message[BUF_SIZE];
    char *request_line_end;
    struct sockaddr_in registered_addr;
    registered_addr.sin_family = AF_INET;
    registered_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &registered_addr.sin_addr);
    // Find the end of the request line
    request_line_end = strstr(message, "\r\n");
    if (!request_line_end)
    {
        printf("Invalid SIP message format\n");
        return;
    }
    // Copy the request line
    size_t request_line_length = request_line_end - message + 2;
    strncpy(modified_message, message, request_line_length);
    modified_message[request_line_length] = '\0';
    // Add new headers
    char new_headers[400];
    snprintf(new_headers, sizeof(new_headers),
             "Via: SIP/2.0/UDP 192.168.37.154:9078;branch=z9hG4bK-forward\r\n"
             "Record-Route: <sip:192.168.37.154:9078;lr>\r\n");
    strcat(modified_message, new_headers);
    // Append the rest of the original message
    strcat(modified_message, request_line_end + 2);
    printf("Original message:\n%s\n", message);
    printf("Modified message:\n%s\n", modified_message);
    printf("Forwarding to IP: %s, Port: %d\n", ip, port);
    // Send the modified message
    if (sendto(sockfd, modified_message, strlen(modified_message), 0, (struct sockaddr *)&registered_addr, sizeof(registered_addr)) < 0)
    {
        perror("sendto() error");
    }
    else
    {
        // Print a message if the message was forwarded successfully
        time_t now;
        time(&now);
        char *time_str = ctime(&now);
        time_str[strlen(time_str) - 1] = '\0'; // Remove the newline character

        printf("[%s] Forwarded message from %s:%d to %s:%d\n", time_str, inet_ntoa(socket_proxy->client_addr_extern.sin_addr), ntohs(socket_proxy->client_addr_extern.sin_port), ip, port);
    }
}

int main(int argc, char *argv[])
{
    Socket_Proxy socket_proxy;
    struct sockaddr_in serv_addr_extern, serv_addr_home;
    socket_proxy.sockfd_extern = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_proxy.sockfd_extern < 0)
    {
        perror("socket()");
        exit(0);
    }
    // config server address extern
    serv_addr_extern.sin_family = AF_INET;
    serv_addr_extern.sin_addr.s_addr = INADDR_ANY;
    serv_addr_extern.sin_port = htons(EXTERN_PORT);
    // bind
    if (bind(socket_proxy.sockfd_extern, (struct sockaddr *)&serv_addr_extern, sizeof(serv_addr_extern)) < 0)
    {
        perror("bind()");
        exit(0);
    }
    // HOME_PORT
    socket_proxy.sockfd_home = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_proxy.sockfd_home < 0)
    {
        perror("socket()");
        exit(0);
    }
    // config server address home
    serv_addr_home.sin_family = AF_INET;
    serv_addr_home.sin_addr.s_addr = INADDR_ANY;
    serv_addr_home.sin_port = htons(HOME_PORT);
    if (bind(socket_proxy.sockfd_home, (struct sockaddr *)&serv_addr_home, sizeof(serv_addr_home)) < 0)
    {
        perror("bind()");
        exit(0);
    }
    // client address home
    socket_proxy.client_addr_home.sin_family = AF_INET;
    socket_proxy.client_addr_home.sin_port = htons(2028);
    inet_pton(AF_INET, "192.168.37.154", &(socket_proxy.client_addr_home.sin_addr));
    shm = init_shared_memory();
    signal(SIGINT, signal_handler);
    // Thread
    pthread_t extern_thread, home_thread;
    // Create thread
    pthread_create(&extern_thread, NULL, handle_socket_extern, (void *)&socket_proxy);
    pthread_create(&home_thread, NULL, handle_socket_home, (void *)&socket_proxy);
    // Join thread
    pthread_join(extern_thread, NULL);
    pthread_join(home_thread, NULL);
    // Destroy mutex
    pthread_mutex_destroy(&lock);
    return 0;
}