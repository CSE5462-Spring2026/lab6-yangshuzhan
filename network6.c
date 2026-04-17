/*Shuzhan Yang
2026/4/15*/
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#include "cJSON.h"
#define MAXPEERS 50

struct FileInfo {
    char filename[100];
    char fullFileHash[65];
    int fileSize;  // <-- CHANGED: Replaced numberOfChunks with fileSize
    char clientIP[MAXPEERS][INET_ADDRSTRLEN];
    int clientPort[MAXPEERS];
    int numberOfPeers;
    struct FileInfo *next;
};

// Global linked list head pointer
struct FileInfo *head = NULL;

// 1. Find file node
struct FileInfo* find_file(const char* hash) {
    struct FileInfo* current = head;
    while (current != NULL) {
        if (strcmp(current->fullFileHash, hash) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// 2. Register or update file information (changed parameter to size)
void register_file(const char* filename, const char* hash, int size, const char* ip, int port) {
    struct FileInfo* existing_file = find_file(hash);

    if (existing_file != NULL) {
        // Check for duplicates
        for (int i = 0; i < existing_file->numberOfPeers; i++) {
            if (strcmp(existing_file->clientIP[i], ip) == 0 && existing_file->clientPort[i] == port) {
                return; // Already exists, ignore
            }
        }
        // Append client
        if (existing_file->numberOfPeers < MAXPEERS) {
            int index = existing_file->numberOfPeers;
            strcpy(existing_file->clientIP[index], ip);
            existing_file->clientPort[index] = port;
            existing_file->numberOfPeers++;
        }
    } else {
        // Create a new node
        struct FileInfo* new_node = (struct FileInfo*)malloc(sizeof(struct FileInfo));
        if (new_node == NULL) return;

        strncpy(new_node->filename, filename, sizeof(new_node->filename) - 1);
        new_node->filename[sizeof(new_node->filename) - 1] = '\0';
        
        strncpy(new_node->fullFileHash, hash, sizeof(new_node->fullFileHash) - 1);
        new_node->fullFileHash[sizeof(new_node->fullFileHash) - 1] = '\0';

        new_node->fileSize = size; // <-- CHANGED: Save the file size

        strcpy(new_node->clientIP[0], ip);
        new_node->clientPort[0] = port;
        new_node->numberOfPeers = 1;

        new_node->next = head;
        head = new_node;
    }
}

// 3. Print all current server records
void print_all_files() {
    struct FileInfo* current = head;
    printf("\n--- Stored File Information ---\n");
    while (current != NULL) {
        printf("Filename: %s\n", current->filename);
        printf("    Full Hash: %s\n", current->fullFileHash);
        printf("    File Size: %d Bytes\n", current->fileSize); // <-- CHANGED
        for (int i = 0; i < current->numberOfPeers; i++) {
            printf("    Client IP: %s, Client Port: %d\n", current->clientIP[i], current->clientPort[i]);
        }
        current = current->next;
    }
    printf("-------------------------------\n\n");
}

// 4. Parse JSON and handle requests (Added socket and src parameters to send responses)
void format_message(char *json_string, const char *client_ip, int client_port, int sockfd, struct sockaddr_in *client_addr) {
    cJSON *root = cJSON_Parse(json_string); 
    if (!root) {
        printf(">>> Error: Invalid JSON format received from %s:%d\n", client_ip, client_port);
        return;
    }

    // Check if this is a "query" request from a client
    cJSON *req_type = cJSON_GetObjectItemCaseSensitive(root, "requestType");
    if (cJSON_IsString(req_type) && strcmp(req_type->valuestring, "query") == 0) {
        
        // Build the queryResponse JSON
        cJSON *response_root = cJSON_CreateObject();
        cJSON_AddStringToObject(response_root, "requestType", "queryResponse");
        
        cJSON *files_array = cJSON_CreateArray();
        struct FileInfo *current = head;
        
        while (current != NULL) {
            cJSON *file_obj = cJSON_CreateObject();
            cJSON_AddStringToObject(file_obj, "filename", current->filename);
            cJSON_AddNumberToObject(file_obj, "fileSize", current->fileSize);
            cJSON_AddStringToObject(file_obj, "fullFileHash", current->fullFileHash);
            
            cJSON_AddItemToArray(files_array, file_obj);
            current = current->next;
        }
        
        cJSON_AddItemToObject(response_root, "files", files_array);
        
        char *response_str = cJSON_PrintUnformatted(response_root); // Unformatted to save bandwidth
        if (response_str) {
            sendto(sockfd, response_str, strlen(response_str), 0, (struct sockaddr*)client_addr, sizeof(*client_addr));
            printf(">>> Responded to 'query' from %s:%d\n", client_ip, client_port);
            free(response_str);
        }
        cJSON_Delete(response_root);

    } else if (cJSON_IsArray(root)) {
        // Handling file registration updates (from Lab 5 logic)
        int array_size = cJSON_GetArraySize(root);
        int stored_count = 0;
        for (int i = 0; i < array_size; i++) {
            cJSON *file_item = cJSON_GetArrayItem(root, i);
            cJSON *name_obj = cJSON_GetObjectItemCaseSensitive(file_item, "filename");
            cJSON *hash_obj = cJSON_GetObjectItemCaseSensitive(file_item, "fullFileHash");
            cJSON *size_obj = cJSON_GetObjectItemCaseSensitive(file_item, "fileSize"); // <-- CHANGED

            if (cJSON_IsString(name_obj) && (name_obj->valuestring != NULL) &&
                cJSON_IsString(hash_obj) && (hash_obj->valuestring != NULL) &&
                cJSON_IsNumber(size_obj)) {
                register_file(name_obj->valuestring, hash_obj->valuestring, size_obj->valueint, client_ip, client_port);
                stored_count++;
            } 
        }
        printf(">>> Processed Array: Successfully stored %d files from %s:%d\n", stored_count, client_ip, client_port);
    } 
    else if (cJSON_IsObject(root)) {
        // =====================================================================
        // ENHANCED FALLBACK: Catch all objects (including "upload" requests)
        // =====================================================================
        cJSON *name_obj = cJSON_GetObjectItemCaseSensitive(root, "filename");
        cJSON *hash_obj = cJSON_GetObjectItemCaseSensitive(root, "fullFileHash");
        cJSON *size_obj = cJSON_GetObjectItemCaseSensitive(root, "fileSize");

        // Case A: The JSON directly contains the file metadata at the root level
        if (name_obj && hash_obj && size_obj) {
            if (cJSON_IsString(name_obj) && cJSON_IsString(hash_obj) && cJSON_IsNumber(size_obj)) {
                register_file(name_obj->valuestring, hash_obj->valuestring, size_obj->valueint, client_ip, client_port);
                printf(">>>  Successfully stored file metadata: %s from %s:%d\n", name_obj->valuestring, client_ip, client_port);
            } else {
                printf(">>>  Error: Data type mismatch in incoming JSON from %s:%d\n", client_ip, client_port);
                printf("    - filename is string? %d\n", cJSON_IsString(name_obj));
                printf("    - fullFileHash is string? %d\n", cJSON_IsString(hash_obj));
                printf("    - fileSize is number? %d (If 0, client might be sending a string!)\n", cJSON_IsNumber(size_obj));
            }
        } 
        // Case B: The JSON is nested (e.g., {"requestType": "upload", "files": [...]})
        else {
            cJSON *files_array = cJSON_GetObjectItemCaseSensitive(root, "files");
            if (cJSON_IsArray(files_array)) {
                int array_size = cJSON_GetArraySize(files_array);
                int stored_count = 0;
                for (int i = 0; i < array_size; i++) {
                    cJSON *file_item = cJSON_GetArrayItem(files_array, i);
                    cJSON *f_name = cJSON_GetObjectItemCaseSensitive(file_item, "filename");
                    cJSON *f_hash = cJSON_GetObjectItemCaseSensitive(file_item, "fullFileHash");
                    cJSON *f_size = cJSON_GetObjectItemCaseSensitive(file_item, "fileSize");

                    if (cJSON_IsString(f_name) && cJSON_IsString(f_hash) && cJSON_IsNumber(f_size)) {
                        register_file(f_name->valuestring, f_hash->valuestring, f_size->valueint, client_ip, client_port);
                        stored_count++;
                    }
                }
                printf(">>> Processed nested 'files' array: Successfully stored %d files from %s:%d\n", stored_count, client_ip, client_port);
            } else {
                // Case C: Completely unrecognized format. Print it out for debugging.
                printf(">>> Warning: Received unhandled Object missing required file fields. Raw JSON:\n%s\n", json_string);
            }
        }
    }

    cJSON_Delete(root); 
}

int main(){
    int socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    int reuse = 1; 
    struct sockaddr_in src;
    socklen_t len = sizeof(src);

    struct sockaddr_in addr;
    struct ip_mreq mreq;
    memset(&addr, 0, sizeof(addr));      
    addr.sin_family = AF_INET;            
    addr.sin_addr.s_addr = htonl(INADDR_ANY); 

    char mcast_ip[32];
    int port;

    printf("Enter multicast IP+port: ");
    int result = scanf("%31s%d", mcast_ip, &port);
    if (result != 2) { 
        printf("Error: Invalid input format.\n");
    } else {
        printf("Success: %s:%d\n", mcast_ip, port);
    }

    mreq.imr_multiaddr.s_addr = inet_addr(mcast_ip); 
    addr.sin_port = htons(port);         

    setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    bind(socketfd, (struct sockaddr*)&addr, sizeof(addr));
    setsockopt(socketfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)); 
    char buf[65536];  

    printf("Server listening for incoming requests...\n");

    while (1) {
        int n = recvfrom(socketfd, buf, sizeof(buf) - 1, 0,
                         (struct sockaddr*)&src, &len);
        if (n < 0) {
            perror("recvfrom");
            break;
        }
        
        buf[n] = 0; 
        
        char *client_ip = inet_ntoa(src.sin_addr);
        int client_port = ntohs(src.sin_port);
        
        // Pass socketfd and &src to reply to queries
        format_message(buf, client_ip, client_port, socketfd, &src);
        
        // Always print current state after processing any message
        print_all_files();
    }
}