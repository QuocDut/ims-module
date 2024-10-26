#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#define SHM_NAME "/Register_user" // NAME OF THE SHM USED
#define EXTERN_PORT 5065
#define HOME_PORT 5066
#define BUF_SIZE 1024

typedef struct User_Memory
{
    char phone_number[20];
    char user_name[20];
    char ip[20];
    char port[5];
    int lifetime;
    time_t timestamp;
    struct User_Memory *next;
} User_Memory;

typedef struct User_Shared_Memory
{
    char phone_number[20];
    char user_name[20];
    char ip[20];
    char port[5];
    int lifetime;
    time_t timestamp;
} User_Shared_Memory;

typedef struct
{
    char from[100];
    char to[100];
    char call_id[100];
    char via[100];
    char cseq[100];
    char contact[100];
    char content_length[100];
} SIP_Headers;
typedef struct
{
    char version[100];
    char owner_session_id[100];
    char session_name[100];
    char connection[100];
    char time[100];
    char media[100];
} SDP;
typedef struct
{
    int sockfd_extern;
    int sockfd_home;
    struct sockaddr_in client_addr_extern;
    struct sockaddr_in client_addr_home;
} Socket_Proxy;

typedef struct CallInfo
{
    char call_id[20];
    char caller_ip[16];
    int caller_port;
    char receiver_ip[16];
    int receiver_port;
    int count;
    struct CallInfo *next;
} CallInfo;

CallInfo *call_list_head = NULL;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
User_Memory *root = NULL;
int register_count = 0;
int countcall = 0;
int StartedRegister = 0;

void parse_headers(const char *message, SIP_Headers *headers, int sockfd, struct sockaddr_in *client_addr); // fixed
void parse_SDP_section(const char *message, SDP *sdp);
void register_user(const char *message); // edited by linked-list
void *init_shared_memory();
void read_register_user(); // edited
int count_register_user();
void send_sip_message(int sockfd, struct sockaddr_in *client_addr, char *method, SIP_Headers *headers, SDP *sdp); // fixed
void forward_sip_message(int sockfd, char *ip, int port, const char *message);
void *handle_socket_extern(void *arg);
void *handle_socket_home(void *arg);
int get_info(const char *extern_buffer, char *phone_number, size_t phone_number_size, char *user_name, size_t user_name_size, const char *header); // fixed
User_Memory *find_registered_User(char *user_name, char *phone_number);                                                                            // edited
void delete_registered_user(User_Memory **root, User_Memory *target_user);
void add_call(const char *call_id, const char *caller_ip, int caller_port, const char *receiver_ip, int receiver_port);
CallInfo *find_call(const char *call_id);
int get_call_id(const char *buffer, char *call_id);
void handle_register(char *extern_buffer, Socket_Proxy *socket_proxy, SIP_Headers *extern_headers);
void remove_call(const char *call_id);
void check_elapsed_time();
void add_expires(char *message);
void *check_expired_users(void *arg);
void signal_handler(int signum);
void restore_from_shared_memory();

int main(int argc, char *argv[])
{
    Socket_Proxy socket_proxy;
    fd_set readfds;
    int max_sd;
    struct sockaddr_in serv_addr_extern, serv_addr_home;

    pthread_mutex_init(&lock, NULL); // Initialize mutex
    pthread_t check_thread;
    pthread_create(&check_thread, NULL, check_expired_users, NULL);
    signal(SIGINT, signal_handler);

    // Create and bind extern socket
    socket_proxy.sockfd_extern = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_proxy.sockfd_extern < 0)
    {
        perror("socket() extern");
        exit(0);
    }

    serv_addr_extern.sin_family = AF_INET;
    serv_addr_extern.sin_addr.s_addr = INADDR_ANY;
    serv_addr_extern.sin_port = htons(EXTERN_PORT);

    if (bind(socket_proxy.sockfd_extern, (struct sockaddr *)&serv_addr_extern, sizeof(serv_addr_extern)) < 0)
    {
        perror("bind() extern");
        exit(0);
    }

    // Create and bind home socket
    socket_proxy.sockfd_home = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_proxy.sockfd_home < 0)
    {
        perror("socket() home");
        exit(0);
    }

    serv_addr_home.sin_family = AF_INET;
    serv_addr_home.sin_addr.s_addr = INADDR_ANY;
    serv_addr_home.sin_port = htons(HOME_PORT);

    if (bind(socket_proxy.sockfd_home, (struct sockaddr *)&serv_addr_home, sizeof(serv_addr_home)) < 0)
    {
        perror("bind() home");
        exit(0);
    }

    socket_proxy.client_addr_home.sin_family = AF_INET;
    socket_proxy.client_addr_home.sin_port = htons(1226);
    if (inet_pton(AF_INET, "192.168.37.154", &(socket_proxy.client_addr_home.sin_addr)) <= 0)
    {
        perror("Invalid address for client_addr_home");
        exit(1);
    }

    restore_from_shared_memory();
    while (1)
    {
        FD_ZERO(&readfds);
        FD_SET(socket_proxy.sockfd_extern, &readfds);
        FD_SET(socket_proxy.sockfd_home, &readfds);

        max_sd = (socket_proxy.sockfd_extern > socket_proxy.sockfd_home) ? socket_proxy.sockfd_extern : socket_proxy.sockfd_home;

        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if (activity < 0)
        {
            perror("select()");
            exit(1);
        }

        if (FD_ISSET(socket_proxy.sockfd_extern, &readfds))
        {
            handle_socket_extern((void *)&socket_proxy);
        }

        if (FD_ISSET(socket_proxy.sockfd_home, &readfds))
        {
            handle_socket_home((void *)&socket_proxy);
        }
    }
    close(socket_proxy.sockfd_extern);
    close(socket_proxy.sockfd_home);
    pthread_mutex_destroy(&lock); // Clean up mutex
    return 0;
}

void *handle_socket_extern(void *arg)
{
    Socket_Proxy *socket_proxy = (Socket_Proxy *)arg;
    int len_extern = sizeof(struct sockaddr_in);
    char extern_buffer[BUF_SIZE];
    SIP_Headers extern_headers;
    SDP extern_sdp;
    int n;
    char phone_number_called[20] = {0};
    char user_name_called[20] = {0};
    char phone_number_caller[20] = {0};
    char user_name_caller[20] = {0};
    char call_id[100];

    n = recvfrom(socket_proxy->sockfd_extern, extern_buffer, sizeof(extern_buffer) - 1, 0,
                 (struct sockaddr *)&socket_proxy->client_addr_extern, &len_extern);
    if (n < 0)
    {
        perror("recvfrom failed");
        return NULL;
    }
    extern_buffer[n] = '\0'; // Null-terminate the received data

    pthread_mutex_lock(&lock);
    printf("Received from User A (extern):\n%s\n", extern_buffer);

    parse_headers(extern_buffer, &extern_headers, socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern);
    parse_SDP_section(extern_buffer, &extern_sdp);

    if (strstr(extern_buffer, "REGISTER"))
    {
        StartedRegister = 1;
        handle_register(extern_buffer, socket_proxy, &extern_headers);
    }
    else if (strstr(extern_buffer, "INVITE"))
    {
        read_register_user();
        if (get_call_id(extern_buffer, call_id))
        {
            printf("Call ID: %s\n", call_id);
            if (get_info(extern_buffer, phone_number_caller, sizeof(phone_number_caller), user_name_caller, sizeof(user_name_caller), "From:"))
            {
                printf("Phone caller: %s\n", phone_number_caller);
                printf("User Name caller: %s\n", user_name_caller);
            }
            else
            {
                printf("Failed to parse From header.\n");
            }
            if (get_info(extern_buffer, phone_number_called, sizeof(phone_number_called), user_name_called, sizeof(user_name_called), "To:"))
            {
                printf("Phone called: %s\n", phone_number_called);
                printf("User Name called: %s\n", user_name_called);
            }
            else
            {
                printf("Failed to parse To header.\n");
            }
            User_Memory *found_receiver = find_registered_User(user_name_called, phone_number_called);
            User_Memory *found_caller = find_registered_User(user_name_caller, phone_number_caller);
            if (found_caller == NULL || found_receiver == NULL)
            {
                send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "404 Not Found", &extern_headers, NULL);
                exit(0);
            }
            printf("Both users are registered.\n");
            char caller_ip[INET_ADDRSTRLEN];
            strcpy(caller_ip, found_caller->port);
            int caller_port = atoi(found_caller->port);
            printf("Caller IP: %s, Caller Port: %d\n", caller_ip, caller_port);
            char receiver_ip[INET_ADDRSTRLEN];
            strcpy(receiver_ip, found_receiver->ip);
            int receiver_port = atoi(found_receiver->port);
            add_call(call_id, caller_ip, caller_port, receiver_ip, receiver_port);
            printf("Forwarding called to IP: %s, PORT: %d\n", receiver_ip, receiver_port);

            forward_sip_message(socket_proxy->sockfd_home, receiver_ip, receiver_port, extern_buffer);
            send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "100 Trying", &extern_headers, &extern_sdp);
        }
    }
    else if (strstr(extern_buffer, "ACK"))
    {
        if (get_call_id(extern_buffer, call_id))
        {
            CallInfo *call_info = find_call(call_id);
            if (call_info != NULL)
            {
                countcall++;
                printf("Number of calls: %d\n", countcall);
                printf("caller IP: %s, PORT: %d\n", call_info->caller_ip, call_info->caller_port);
                printf("Forwarding ACK to IP: %s, PORT: %d\n", call_info->receiver_ip, call_info->receiver_port);
                forward_sip_message(socket_proxy->sockfd_home, call_info->receiver_ip, call_info->receiver_port, extern_buffer);
            }
            else
            {
                printf("Call session info not found for ACK.\n");
            }
        }
        else
        {
            printf("Call-ID not found in ACK.\n");
        }
    }
    else if (strstr(extern_buffer, "BYE"))
    {
        if (get_call_id(extern_buffer, call_id))
        {
            CallInfo *call_info = find_call(call_id);
            if (call_info != NULL)
            {
                call_info->count = 1;
                printf("Forwarding BYE to IP: %s, PORT: %d\n", call_info->receiver_ip, call_info->receiver_port);
                forward_sip_message(socket_proxy->sockfd_home, call_info->receiver_ip, call_info->receiver_port, extern_buffer);
            }
            else
            {
                printf("Call session info not found for BYE.\n");
            }
        }
        else
        {
            printf("Call-ID not found in BYE.\n");
        }
    }

    pthread_mutex_unlock(&lock);
    return NULL;
}

void *handle_socket_home(void *arg)
{
    Socket_Proxy *socket_proxy = (Socket_Proxy *)arg;
    int len_home = sizeof(struct sockaddr_in);
    char home_buffer[BUF_SIZE];
    SIP_Headers home_headers;
    SDP home_sdp;
    char call_id[100];
    int m;
    m = recvfrom(socket_proxy->sockfd_home, home_buffer, sizeof(home_buffer) - 1, 0,
                 (struct sockaddr *)&socket_proxy->client_addr_home, &len_home);

    if (m < 0)
    {
        perror("recvfrom failed for home");
        return 0;
    }
    home_buffer[m] = '\0';
    printf("Received from User B (home):\n%s\n", home_buffer);
    pthread_mutex_lock(&lock);
    // CS
    parse_headers(home_buffer, &home_headers, socket_proxy->sockfd_home, &socket_proxy->client_addr_home);
    parse_SDP_section(home_buffer, &home_sdp);
    if (strstr(home_buffer, "100 Trying"))
    {
        printf("100 Trying from B\n");
    }
    else if (strstr(home_buffer, "401 Unauthorized"))
    {
        send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "401 Unauthorized", &home_headers, NULL);
    }
    else if (strstr(home_buffer, "180 Ringing"))
    {
        send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "180 Ringing", &home_headers, &home_sdp);
    }
    else if (strstr(home_buffer, "200 OK"))
    {
        send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "200 OK", &home_headers, &home_sdp);
        if (strstr(home_buffer, "2 REGISTER"))
        {
            add_expires(home_buffer);
            read_register_user();
        }
        if (StartedRegister == 1)
            StartedRegister = 0;
        else
        {
            if (get_call_id(home_buffer, call_id))
            {
                CallInfo *call_info = find_call(call_id);
                if (call_info->count == 1)
                {
                    call_info->count = 0;
                    countcall--;
                    printf("Number of calls: %d\n ", countcall);
                    remove_call(call_id);
                }
            }
        }
    }
    pthread_mutex_unlock(&lock);
}

void handle_register(char *extern_buffer, Socket_Proxy *socket_proxy, SIP_Headers *extern_headers)
{
    char registered_ip[20];
    int registered_port = 1226;
    if (register_count == 0)
    {
        strcpy(registered_ip, "192.168.37.154");
        forward_sip_message(socket_proxy->sockfd_home, registered_ip, registered_port, extern_buffer);
        send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "100 Trying", extern_headers, NULL);
        register_count++;
    }
    else if (register_count == 1)
    {
        register_user(extern_buffer);
        forward_sip_message(socket_proxy->sockfd_home, registered_ip, registered_port, extern_buffer);
        send_sip_message(socket_proxy->sockfd_extern, &socket_proxy->client_addr_extern, "100 Trying", extern_headers, NULL);
        register_count--;
    }
}

void add_call(const char *call_id, const char *caller_ip, int caller_port, const char *receiver_ip, int receiver_port)
{
    CallInfo *new_call = (CallInfo *)malloc(sizeof(CallInfo));
    if (new_call == NULL)
    {
        perror("Failed to allocate memory for new call");
        return;
    }
    strcpy(new_call->call_id, call_id);
    strcpy(new_call->caller_ip, caller_ip);
    new_call->caller_port = caller_port;
    strcpy(new_call->receiver_ip, receiver_ip);
    new_call->receiver_port = receiver_port;
    new_call->next = NULL;

    if (call_list_head == NULL)
    {
        call_list_head = new_call;
    }
    else
    {
        new_call->next = call_list_head;
        call_list_head = new_call;
    }
}

CallInfo *find_call(const char *call_id)
{
    CallInfo *current = call_list_head;
    while (current != NULL)
    {
        if (strcmp(current->call_id, call_id) == 0)
        {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

void remove_call(const char *call_id)
{
    CallInfo *current = call_list_head;
    CallInfo *previous = NULL;

    while (current != NULL)
    {
        if (strcmp(current->call_id, call_id) == 0)
        {
            if (previous == NULL)
            {
                call_list_head = current->next;
            }
            else
            {
                previous->next = current->next;
            }
            free(current);
            return;
        }
        previous = current;
        current = current->next;
    }
}

int get_call_id(const char *buffer, char *call_id)
{
    const char *call_id_header = "Call-ID:";
    const char *start = strstr(buffer, call_id_header);

    if (start == NULL)
    {
        return 0;
    }
    start += strlen(call_id_header);
    while (*start == ' ')
    {
        start++;
    }
    const char *end = strstr(start, "\r\n");
    if (end == NULL)
    {
        return 0;
    }
    size_t length = end - start;
    if (length >= 20)
    {
        length = 19;
    }
    strncpy(call_id, start, length);
    call_id[length] = '\0';
    printf("Caller ID: %s\n", call_id);
    return 1;
}

void *init_shared_memory()
{
    int user_count = count_register_user();
    size_t shm_size = sizeof(User_Shared_Memory) * user_count;

    // Open shared memory object
    int shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1)
    {
        perror("shm_open");
        return NULL;
    }

    // Set the size of the shared memory object
    if (ftruncate(shm_fd, shm_size) == -1)
    {
        perror("ftruncate");
        close(shm_fd);
        return NULL;
    }

    // Map the shared memory object to memory
    User_Shared_Memory *shm_base = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_base == MAP_FAILED)
    {
        perror("mmap");
        close(shm_fd);
        return NULL;
    }

    // Copy data from linked list to shared memory
    User_Memory *current = root;
    for (int i = 0; i < user_count; i++)
    {
        if (current == NULL)
            break;
        strcpy(shm_base[i].phone_number, current->phone_number);
        strcpy(shm_base[i].user_name, current->user_name);
        strcpy(shm_base[i].ip, current->ip);
        strcpy(shm_base[i].port, current->port);
        shm_base[i].lifetime = current->lifetime;
        shm_base[i].timestamp = current->timestamp;
        current = current->next;
    }

    // Unmap and close the shared memory
    munmap(shm_base, shm_size);
    close(shm_fd);
}

void register_user(const char *message)
{
    User_Memory *new_user = (User_Memory *)malloc(sizeof(User_Memory));
    if (new_user == NULL)
    {
        perror("malloc failed");
        return;
    }
    const char *from = strstr(message, "From:");
    if (from)
    {
        const char *start = strstr(from, "sip:");
        if (start)
        {
            start += 4; // Skip the "sip:"
            const char *end = strchr(start, '@');
            if (end && (end - start < sizeof(new_user->phone_number)))
            {
                strncpy(new_user->phone_number, start, end - start);
                new_user->phone_number[end - start] = '\0';
            }
        }

        const char *name_start = strchr(from, ' ');
        const char *name_end = strstr(from, " <");
        if (name_start && name_end && name_start < name_end)
        {
            size_t name_length = name_end - name_start;
            if (name_length < sizeof(new_user->user_name))
            {
                strncpy(new_user->user_name, name_start + 1, name_length - 1);
                new_user->user_name[name_length - 1] = '\0';
            }
        }
    }

    const char *contact = strstr(message, "Contact:");
    if (contact)
    {
        const char *start = strstr(contact, "sip:");
        if (start)
        {
            start += 4;
            const char *end_ip = strchr(start, ':');
            const char *end_port = strchr(end_ip + 1, '>'); // Find the end of the port number

            if (end_ip && end_port && (end_ip - start < sizeof(new_user->ip)))
            {
                strncpy(new_user->ip, start, end_ip - start);
                new_user->ip[end_ip - start] = '\0';

                size_t port_len = end_port - (end_ip + 1);
                if (port_len > 0 && port_len < sizeof(new_user->port))
                {
                    strncpy(new_user->port, end_ip + 1, port_len);
                    new_user->port[port_len] = '\0';
                }
            }
        }
    }
    if (strlen(new_user->phone_number) > 0 && strlen(new_user->user_name) > 0)
    {
        if (root == NULL || root->phone_number[0] == '\0')
        {
            root = new_user;
            new_user->next = NULL;
        }
        else
        {
            new_user->next = root;
            root = new_user;
        }
    }
    else
    {
        free(new_user);
    }
}

int get_info(const char *extern_buffer, char *phone_number, size_t phone_number_size, char *user_name, size_t user_name_size, const char *header)
{
    const char *header_field = strstr(extern_buffer, header);
    if (header_field)
    {
        const char *start = strstr(header_field, "sip:");
        if (start)
        {
            start += 4;

            const char *end = strchr(start, '@');
            if (end)
            {
                size_t length = end - start;
                if (length >= phone_number_size)
                    length = phone_number_size - 1;
                strncpy(phone_number, start, length);
                phone_number[length] = '\0';

                const char *name_start = strstr(header_field, " ") + 1;
                const char *name_end = strchr(name_start, '<');

                if (name_end)
                {
                    length = name_end - name_start - 1;
                    if (length >= user_name_size)
                        length = user_name_size - 1;
                    strncpy(user_name, name_start, length);
                    user_name[length] = '\0';
                }
                else
                {
                    length = end - start;
                    if (length >= user_name_size)
                        length = user_name_size - 1;
                    strncpy(user_name, name_start, length);
                    user_name[length] = '\0';
                }

                return 1;
            }
        }
    }
    return 0;
}

void read_register_user()
{
    User_Memory *current = root;
    int i = 1;
    if (root == NULL)
    {
        printf("No users in shared memory!!!\n");
        return;
    }
    printf("All users in shm: \n");
    while (current != NULL)
    {
        printf("User %d: \n", i);
        printf("Phone Number: %s\n", current->phone_number);
        printf("User Name: %s\n", current->user_name);
        printf("IP: %s\n", current->ip);
        printf("Port: %s\n", current->port);
        printf("Lifetime: %d\n", current->lifetime);
        printf("\n");
        current = current->next;
        i++;
    }
}

void parse_headers(const char *message, SIP_Headers *headers, int sockfd, struct sockaddr_in *client_addr)
{
    char message_copy[BUF_SIZE];
    strncpy(message_copy, message, BUF_SIZE - 1);
    message_copy[BUF_SIZE - 1] = '\0';

    char *line = strtok(message_copy, "\r\n");
    while (line != NULL)
    {
        if (strncmp(line, "To:", 3) == 0)
        {
            strncpy(headers->to, line + 4, 99);
            headers->to[99] = '\0';
        }
        else if (strncmp(line, "From:", 5) == 0)
        {
            strncpy(headers->from, line + 6, 99);
            headers->from[99] = '\0';
        }
        else if (strncmp(line, "Via:", 4) == 0)
        {
            strncpy(headers->via, line + 5, 99);
            headers->via[99] = '\0';
        }
        else if (strncmp(line, "Call-ID:", 8) == 0)
        {
            strncpy(headers->call_id, line + 9, 99);
            headers->call_id[99] = '\0';
        }
        else if (strncmp(line, "CSeq:", 5) == 0)
        {
            strncpy(headers->cseq, line + 6, 99);
            headers->cseq[99] = '\0';
        }
        else if (strncmp(line, "Contact:", 8) == 0)
        {
            strncpy(headers->contact, line + 9, 99);
            headers->contact[99] = '\0';
        }
        else if (strncmp(line, "Content-Length:", 15) == 0)
        {
            strncpy(headers->content_length, line + 16, 99);
            headers->content_length[99] = '\0';
        }
        line = strtok(NULL, "\r\n");
    }
    if (strlen(headers->to) == 0 || strlen(headers->via) == 0 || strlen(headers->from) == 0 || strlen(headers->call_id) == 0 || strlen(headers->cseq) == 0 || strlen(headers->content_length) == 0)
    {
        printf("Missing To header.\n");
        send_sip_message(sockfd, client_addr, "400 Bad Request", headers, NULL);
        exit(0);
    }
}

void parse_SDP_section(const char *message, SDP *sdp)
{
    char message_copy[BUF_SIZE];
    strncpy(message_copy, message, BUF_SIZE - 1);
    message_copy[BUF_SIZE - 1] = '\0';

    char *line = strtok(message_copy, "\r\n");
    while (line != NULL)
    {
        if (strncmp(line, "v=", 2) == 0)
        {
            strncpy(sdp->version, line + 2, 99);
            sdp->version[99] = '\0';
        }
        else if (strncmp(line, "o=", 2) == 0)
        {
            strncpy(sdp->owner_session_id, line + 2, 99);
            sdp->owner_session_id[99] = '\0';
        }
        else if (strncmp(line, "s=", 2) == 0)
        {
            strncpy(sdp->session_name, line + 2, 99);
            sdp->session_name[99] = '\0';
        }

        else if (strncmp(line, "c=", 2) == 0)
        {
            strncpy(sdp->connection, line + 2, 99);
            sdp->connection[99] = '\0';
        }
        else if (strncmp(line, "t=", 2) == 0)
        {
            strncpy(sdp->time, line + 2, 99);
            sdp->time[99] = '\0';
        }
        else if (strncmp(line, "m=", 2) == 0)
        {
            strncpy(sdp->media, line + 2, 99);
            sdp->media[99] = '\0';
        }
        line = strtok(NULL, "\r\n");
    }
}

void send_sip_message(int sockfd, struct sockaddr_in *client_addr, char *method, SIP_Headers *headers, SDP *sdp)
{
    char response[BUF_SIZE] = "";
    char sdp_message[BUF_SIZE] = "";

    snprintf(response, sizeof(response),
             "SIP/2.0 %s\r\n"
             "Call-ID: %s\r\n"
             "CSeq: %s\r\n"
             "From: %s\r\n"
             "To: %s\r\n"
             "Via: %s\r\n"
             "Contact: %s\r\n"
             "Record-Route: <sip:%s:5066;lr>\r\n"
             "Content-Length: %s\r\n",
             method, headers->call_id, headers->cseq, headers->from, headers->to, headers->via, headers->contact, inet_ntoa(client_addr->sin_addr), headers->content_length);
    if (sdp != NULL)
    {
        // ckeck data
        if (strlen(sdp->version) > 0 && strlen(sdp->owner_session_id) > 0 && strlen(sdp->session_name) > 0 && strlen(sdp->connection) > 0 &&
            strlen(sdp->time) > 0 && strlen(sdp->media) > 0)
        {
            snprintf(sdp_message, sizeof(sdp_message),
                     "v=%s\r\n"
                     "o=%s\r\n"
                     "s=%s\r\n"
                     "c=%s\r\n"
                     "t=%s\r\n"
                     "m=%s\r\n",
                     sdp->version, sdp->owner_session_id, sdp->session_name, sdp->connection, sdp->time, sdp->media);
            if (strlen(sdp_message) > 0)
            {
                strncat(response, sdp_message, sizeof(response) - strlen(response) - 1);
            }
        }
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

User_Memory *find_registered_User(char *user_name, char *phone_number)
{
    User_Memory *current = root;
    while (current != NULL)
    {
        if (strcmp(current->user_name, user_name) == 0 && strcmp(current->phone_number, phone_number) == 0)
        {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// free
void delete_registered_user(User_Memory **root, User_Memory *target_user)
{
    struct User_Memory *current = *root;
    struct User_Memory *prev = NULL;
    if (current == NULL)
        return;

    if (current == target_user)
    {
        *root = current->next;
        free(current);
        return;
    }
    while (current != NULL && current != target_user)
    {
        prev = current;
        current = current->next;
    }

    // If the key is not present
    if (current == NULL)
        return;

    // Remove the node
    prev->next = current->next;
    free(current);
}

void forward_sip_message(int sockfd, char *ip, int port, const char *message)
{
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
             "Via: SIP/2.0/UDP 192.168.37.154:5066;branch=z9hG4bK-forward\r\n"
             "Record-Route: <sip:192.168.37.154:5066;lr>\r\n");
    strcat(modified_message, new_headers);

    // Append the rest of the original message
    strcat(modified_message, request_line_end + 2);

    printf("Original message:\n%s\n", message);
    printf("Modified message:\n%s\n", modified_message);

    // Send the modified message
    if (sendto(sockfd, modified_message, strlen(modified_message), 0, (struct sockaddr *)&registered_addr, sizeof(registered_addr)) < 0)
    {
        perror("sendto() error");
    }
    else
    {
        printf("Forwarded modified message\n");
    }
}

void check_elapsed_time()
{
    User_Memory *current = root;
    while (current != NULL)
    {
        time_t elapsed_time = time(NULL) - current->timestamp;
        time_t elapsed_time_ms = elapsed_time * 1000;
        if (elapsed_time_ms > current->lifetime)
        {
            printf("Elapsed time of user %s, phone number %s, port number %s exceeded! Delete this user\n", current->user_name, current->phone_number, current->port);
            ;
            delete_registered_user(&root, current);
        }
        current = current->next;
        if (current == NULL)
            break;
    }
}

void add_expires(char *message)
{
    char name[100];
    char phone_num[100];
    if (strstr(message, "From: "))
    {
        sscanf(strstr(message, "From: "), "From: %19[^ <] <sip:%19[^@]", name, phone_num);
    }
    else
        printf("\n\nfrom failed\n\n");
    User_Memory *current = find_registered_User(name, phone_num);
    if (current == NULL)
    {
        printf("\n\nuser not found\n\n");
        return;
    }
    if (strstr(message, "expires="))
    {
        char period[100];
        sscanf(strstr(message, "expires="), "expires=%15[^\r\n]", period);
        current->lifetime = atoi(period);
        current->timestamp = time(NULL);
        printf("\n\nParse expires time success\n\n");
    }
}

void *check_expired_users(void *arg)
{
    while (1)
    {
        sleep(1);
        pthread_mutex_lock(&lock);
        check_elapsed_time();
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

int count_register_user()
{
    User_Memory *current = root;
    int count = 0;
    if (root == NULL)
    {
        return 0;
    }
    while (current != NULL)
    {
        current = current->next;
        count++;
    }
    return count;
}

void signal_handler(int signum)
{
    if (signum == SIGINT)
    {
        printf("Caught signal %d, terminating and saving state...\n", signum);
        init_shared_memory();
        exit(0);
    }
}

void restore_from_shared_memory()
{
    // Open shared memory object
    int shm_fd = shm_open(SHM_NAME, O_RDWR, 0666);
    if (shm_fd == -1)
    {
        if (errno == ENOENT)
        {
            printf("Shared memory not found, no users to retrieve...\n");
        }
        else
        {
            perror("shm_open");
        }
        return;
    }

    // Get the size of the shared memory object
    struct stat shm_stat;
    if (fstat(shm_fd, &shm_stat) == -1)
    {
        perror("fstat");
        close(shm_fd);
        return;
    }

    size_t shm_size = shm_stat.st_size;
    int user_count = shm_size / sizeof(User_Shared_Memory);

    if (user_count <= 0)
    {
        printf("No data in shared memory.\n");
        close(shm_fd);
        return;
    }

    // Map the shared memory object
    User_Shared_Memory *shm_base = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_base == MAP_FAILED)
    {
        perror("mmap");
        close(shm_fd);
        return;
    }

    // Read data from shared memory into linked list
    for (int i = 0; i < user_count; i++)
    {
        User_Memory *new_user = (User_Memory *)malloc(sizeof(User_Memory));
        strcpy(new_user->phone_number, shm_base[i].phone_number);
        strcpy(new_user->user_name, shm_base[i].user_name);
        strcpy(new_user->ip, shm_base[i].ip);
        strcpy(new_user->port, shm_base[i].port);
        new_user->lifetime = shm_base[i].lifetime;
        new_user->timestamp = shm_base[i].timestamp;
        if (root == NULL)
        {
            root = new_user;
            new_user->next = NULL;
        }
        else
        {
            new_user->next = root;
            root = new_user;
        }
    }
    printf("Retrieved %d users from shared memory.\n", user_count);

    // Unmap and close shared memory
    munmap(shm_base, shm_size);
    close(shm_fd);

    if (shm_unlink(SHM_NAME) == -1)
    {
        perror("shm_unlink");
    }
    else
    {
        printf("Shared memory successfully deleted after retrieving.\n");
    }
}