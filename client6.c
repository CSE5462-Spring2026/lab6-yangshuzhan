#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <sys/stat.h>   
#include <sys/types.h>  
#include <errno.h>      
#include <dirent.h>
#include "cJSON.h" 

int sendStuff(char *buffer, int sd, struct sockaddr_in server_address);
void makeSocket(int *sd, char *argv[], struct sockaddr_in *server_address);
FILE * openFile();
char *rtrim(char *s);
char fileName [100]; 
#define MAX_FIELDS 20
#define MAX_LEN 100

typedef struct {
    char keys[MAX_FIELDS][MAX_LEN];   // field names
    char values[MAX_FIELDS][MAX_LEN]; // 
    int count;                        // num of fields
} json;

//parse string "Key:Value Key2:Value2" 
json linetojson(char *line) {
    json currentJson;
    currentJson.count = 0;
    char *ptr = line;

    while (*ptr != '\0' && currentJson.count < MAX_FIELDS) {
        while (*ptr == ' ' || *ptr == '\n' || *ptr == '\r') ptr++;
        if (*ptr == '\0') break; 

        char *colon = strchr(ptr, ':');
        if (!colon) break; 

        int keyLen = colon - ptr;
        if (keyLen >= MAX_LEN) keyLen = MAX_LEN - 1;
        strncpy(currentJson.keys[currentJson.count], ptr, keyLen);
        currentJson.keys[currentJson.count][keyLen] = '\0';

        char *valStart = colon + 1;
        char *valEnd = NULL;
        int isQuoted = 0;

        if (*valStart == '"') {
            isQuoted = 1;
            valStart++; 
            valEnd = strchr(valStart, '"');
            if (!valEnd) {
                valEnd = valStart + strlen(valStart);
            }
        } else {
            valEnd = strchr(valStart, ' ');
            if (!valEnd) {
                valEnd = valStart + strlen(valStart);
            }
        }

        int valLen = valEnd - valStart;
        while (valLen > 0 && (valStart[valLen-1] == '\n' || valStart[valLen-1] == '\r')) {
            valLen--;
        }

        if (valLen >= MAX_LEN) valLen = MAX_LEN - 1;
        strncpy(currentJson.values[currentJson.count], valStart, valLen);
        currentJson.values[currentJson.count][valLen] = '\0';

        currentJson.count++;

        if (isQuoted) {
            ptr = valEnd + 1;
        } else {
            ptr = valEnd; }
    }
    return currentJson;
}

//format into json (currently unused, but kept)
void jsontostring(json *data, char *buffer) {
    strcpy(buffer, "{\n"); // begin
    char temp[256];
    for (int i = 0; i < data->count; i++) {
        sprintf(temp, "  \"%s\": \"%s\"", data->keys[i], data->values[i]);
        strcat(buffer, temp);
        if (i < data->count - 1) {
            strcat(buffer, ",\n");
        } else {
            strcat(buffer, "\n");
        }
    }
    strcat(buffer, "}"); // end
}

//  Modified the function signature to add the cJSON *json_array parameter 
int processfile(char *path_to_file, char *fileName, char *base_dir, cJSON *json_array){  
    FILE * fptr;
    fptr = fopen(path_to_file,"rb"); // open the file with the data to send

#define CHUNK_SIZE (500 * 1024) // 512000 bytes

    if (fptr == NULL) {
        printf("loading error");
        return -1;
    }

    unsigned char buffer[CHUNK_SIZE];
    size_t bytesRead;
    
    // 1. create CHUNKS dir
    if (mkdir("CHUNKS", 0777) == -1) {
        if (errno != EEXIST) {
            perror("Could not create directory");
            exit(1);
        }
    }
    
    char hashes[100][65];
    int chunk_count = 0;
    size_t totalFileSize = 0;
    
    // loop to read until EOF
    SHA256_CTX whole_file_hash_ctx;
    SHA256_Init(&whole_file_hash_ctx);

    while ((bytesRead = fread(buffer, 1, CHUNK_SIZE, fptr)) > 0) {
        totalFileSize += bytesRead;
        SHA256_Update(&whole_file_hash_ctx, buffer, bytesRead);
        
        // A. calc SHA256 hash for current chunk
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(buffer, bytesRead, hash);

        // B. convert hash to hex string (as filename)
        char hexHash[SHA256_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(hexHash + (i * 2), "%02x", hash[i]);
        }
        hexHash[64] = '\0'; 

        chunk_count++;
        
        // D. build file path and save chunk
        char chunkPath[256];
        snprintf(chunkPath, sizeof(chunkPath), "CHUNKS/%s", hexHash);

        // Save current hash for later JSON processing
        strcpy(hashes[chunk_count], hexHash);

        FILE *chunkFile = fopen(chunkPath, "wb"); // use binary write mode
        if (chunkFile) {
            fwrite(buffer, 1, bytesRead, chunkFile);
            fclose(chunkFile);
        } else {
            fprintf(stderr, "Error: Could not write chunk file %s\n", hexHash);
        }
    }
    fclose(fptr);

    //final hash
    unsigned char final_hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(final_hash, &whole_file_hash_ctx);

    char finalHexHash[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(finalHexHash + (i * 2), "%02x", final_hash[i]);
    }
    finalHexHash[64] = '\0';

    /* --- Use cJSON to assemble current file info and add to array ---  */
    
    // 1. Create an independent JSON object for the current file
    cJSON *file_obj = cJSON_CreateObject();
    
    // 2. Add core fields
    cJSON_AddStringToObject(file_obj, "filename", fileName);
    cJSON_AddNumberToObject(file_obj, "fileSize", totalFileSize);
    cJSON_AddNumberToObject(file_obj, "numberOfChunks", chunk_count);
    
    // 3. Process the chunk hash array (chunk_hashes)
    cJSON *hash_array = cJSON_CreateArray(); 
    for (int i = 1; i <= chunk_count; i++) {
        cJSON_AddItemToArray(hash_array, cJSON_CreateString(hashes[i])); 
    }
    cJSON_AddItemToObject(file_obj, "chunk_hashes", hash_array);
    
    // 4. Add the full file hash
    cJSON_AddStringToObject(file_obj, "fullFileHash", finalHexHash);

    // 5. Append the current file object to the array passed from main
    cJSON_AddItemToArray(json_array, file_obj);

    return 0; 
}


int main(int argc, char *argv[])
{
    if (argc < 4) {
        printf("Usage: %s <directory_path> <ipaddr> <portnumber>\n", argv[0]);
        exit(1);
    }
    
    int sd; 
    struct sockaddr_in server_address;  
    if (argc >= 4) {
        char *argv_for_socket[] = {argv[0], argv[2], argv[3]};
        makeSocket(&sd, argv_for_socket, &server_address);
    }
    
    char *targetDir = argv[1];
    DIR *dirPtr = opendir(targetDir);
    struct dirent *entry;

    if (dirPtr == NULL) {
        perror("Unable to open directory");
        exit(1);
    }

    // Create an empty JSON array to collect all file info 
    cJSON *json_array = cJSON_CreateArray();
    int files_processed = 0;

    // Loop through all files in the directory
    while ((entry = readdir(dirPtr)) != NULL) {
        // Exclude directories and hidden files
        if (strchr(entry->d_name, ':') != NULL) continue;
        if (entry->d_type == DT_REG) {
            char fullFilePath[512];
            snprintf(fullFilePath, sizeof(fullFilePath), "%s/%s", targetDir, entry->d_name);
            
            // Pass json_array so processfile can populate it
            processfile(fullFilePath, entry->d_name, targetDir, json_array);
            files_processed++;
        }
    }
    closedir(dirPtr);

    //  After iterating through all files, convert the JSON array to a string and send it at once 
    if (files_processed > 0) {
        char *final_json_string = cJSON_PrintUnformatted(json_array); // Save network bandwidth, do not add indentation
        if (final_json_string) {
            printf("Sending JSON Array (%d files)...\n", files_processed);
            sendStuff(final_json_string, sd, server_address); // Send the large packet!
            free(final_json_string); // Free memory after use
        }
    } else {
        printf("No valid files found to process.\n");
    }

    // Free cJSON structure memory
    cJSON_Delete(json_array);

    /* ========================================================= */
    /* PROJECT 6 ADDITIONS: INTERACTIVE MENU & FILE RETRIEVAL    */
    /* ========================================================= */

    // Set a timeout for recvfrom to prevent blocking indefinitely when waiting for servers
    struct timeval tv;
    tv.tv_sec = 2;  // 2 seconds timeout
    tv.tv_usec = 0;
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    int choice;
    char recv_buf[65536];

    while (1) {
        // [cite: 239, 240, 276-278]
        printf("\nSelect an option:\n");
        printf("1. View Available Files\n");
        printf("2. Exit\n");
        printf("> ");
        
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n'); // clear bad input
            continue;
        }

        if (choice == 2) {
            break;
        } else if (choice == 1) {
            // [cite: 233, 237, 238] Create and send the query request
            char *query_msg = "{\"requestType\": \"query\"}";
            sendStuff(query_msg, sd, server_address);
            
            // [cite: 241, 266, 280-283] Print the table header
            printf("\nFiles Available Across Servers:\n");
            printf("------------------------------------------------\n");
            printf("Choice | File Name            | Size       | Full Hash\n");
            printf("------------------------------------------------\n");

            int choice_counter = 1;
            struct sockaddr_in sender_addr;
            socklen_t sender_len = sizeof(sender_addr);

            // Loop to receive responses from multiple servers
            while (1) {
                int n = recvfrom(sd, recv_buf, sizeof(recv_buf) - 1, 0, 
                                 (struct sockaddr *)&sender_addr, &sender_len);
                
                // If n < 0, the 2-second timeout has likely been reached, exit receiving loop
                if (n < 0) {
                    break; 
                }
                
                recv_buf[n] = '\0';

                // Parse the received JSON
                cJSON *response_json = cJSON_Parse(recv_buf);
                if (response_json == NULL) continue;

                // [cite: 227, 232, 234] Check if it is a valid queryResponse
                cJSON *req_type = cJSON_GetObjectItemCaseSensitive(response_json, "requestType");
                if (cJSON_IsString(req_type) && strcmp(req_type->valuestring, "queryResponse") == 0) {
                    
                    // [cite: 243, 249, 257] Extract the "files" array
                    cJSON *files_array = cJSON_GetObjectItemCaseSensitive(response_json, "files");
                    if (cJSON_IsArray(files_array)) {
                        int array_size = cJSON_GetArraySize(files_array);
                        
                        // Loop through the files array and print each file's metadata
                        for (int i = 0; i < array_size; i++) {
                            cJSON *file_item = cJSON_GetArrayItem(files_array, i);
                            
                            cJSON *name_obj = cJSON_GetObjectItemCaseSensitive(file_item, "filename");
                            cJSON *size_obj = cJSON_GetObjectItemCaseSensitive(file_item, "fileSize");
                            cJSON *hash_obj = cJSON_GetObjectItemCaseSensitive(file_item, "fullFileHash");

                            // [cite: 259-261, 284-286]
                            if (cJSON_IsString(name_obj) && cJSON_IsNumber(size_obj) && cJSON_IsString(hash_obj)) {
                                printf("%-6d | %-20s | %-8d B | %s\n", 
                                       choice_counter++, 
                                       name_obj->valuestring, 
                                       size_obj->valueint, 
                                       hash_obj->valuestring);
                            }
                        }
                    }
                }
                cJSON_Delete(response_json);
            }
        }
    }

    return 0;
}


/******************************************************************/
/* this function actually does the sending of the data            */
/******************************************************************/
int sendStuff(char *buffer, int sd, struct sockaddr_in server_address){

  int rc = 0;
  rc = sendto(sd, buffer, strlen(buffer), 0,
        (struct sockaddr *) &server_address, sizeof(server_address));

  return (0); 
}

/******************************************************************/
/* this function will create a socket and fill in the address of  */
/* the server                                                    */
/******************************************************************/
void makeSocket(int *sd, char *argv[], struct sockaddr_in *server_address){
  int i; // loop variable
  struct sockaddr_in inaddr; // use this as a temp value for checking validity
  int portNumber; // get this from command line
  char serverIP[50]; // overkill on size
  
  if (!inet_pton(AF_INET, argv[1], &inaddr)){
    printf ("error, bad ip address\n");
    exit (1); 
  }
  
  *sd = socket(AF_INET, SOCK_DGRAM, 0); 
  int reuse =1;
  setsockopt(*sd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));

  if (*sd == -1){ 
    perror ("socket");
    exit(1); 
  }

  for (i=0;i<strlen(argv[2]); i++){
    if (!isdigit(argv[2][i]))
      {
  printf ("The Portnumber isn't a number!\n");
  exit(1);
      }
  }

  portNumber = strtol(argv[2], NULL, 10); 
  if ((portNumber > 65535) || (portNumber < 0)){
    printf ("you entered an invalid socket number\n");
    exit (1);
  }
  
  strcpy(serverIP, argv[1]); 

  server_address->sin_family = AF_INET; 
  server_address->sin_port = htons(portNumber); 
  server_address->sin_addr.s_addr = inet_addr(serverIP); 
}

/******************************************************************/
/* this function will ask the user for the name of the input file */
/* it will then open that file and pass pack the file descriptor  */
/******************************************************************/

FILE * openFile (){
  FILE * fptr = NULL; 
  while (1){
    memset (fileName, 0,100); 
    printf ("What is the name of the messages file you would like to use? ");
    char *ptr = fgets(fileName, sizeof(fileName), stdin);
    if (ptr == NULL){
      perror ("fgets");
      exit (1);
    }

    ptr = rtrim(ptr);
    if (ptr == NULL){                                                                                   
      printf ("you didn't enter anything, try again.\n");
    }
    else{
      fptr = fopen (fileName, "r");
      if (fptr == NULL){
  printf ("error opening the file, try again\n");
  continue; 
      }
      return fptr;
      break; 
    }
  } 
}

/* this trims characters from a string */
char *rtrim(char *s)
{
    char* back = s + strlen(s);
    while(isspace(*--back));
    *(back+1) = '\0';
    return s;
}