#include "cctk.h"
#include "cctk_Arguments.h"
#include "cctk_Parameters.h"
#include "cctk_Functions.h"

#include<unistd.h>
#include<string.h>
#include<openssl/sha.h>
#include <stdlib.h>
#include <stdio.h>

#define FILE_TO_HASH "/home/lukas/cactus/debian-live-12.5.0-amd64-standard.iso" // "/home/lukas/cactus/file_to_hash.txt"


unsigned char* calculateSHA1(unsigned char * text, size_t len)
{

    unsigned char* sha1_digest = malloc(sizeof(char)*SHA_DIGEST_LENGTH);
    SHA1(text, len, sha1_digest);
    // SHA_CTX context;

    // if(!SHA1_Init(&context))
    //     return NULL;

    // if(!SHA1_Update(&context, text, len))
    // {
    //     return NULL;
    // }

    // if(!SHA1_Final(sha1_digest, &context))
    //     return NULL;


    return sha1_digest;
}

char* sha1_to_string(unsigned char* sha1)
{
    char *sha1hash = (char *)malloc(sizeof(char) * 41);
    sha1hash[40] = '\0';
    int i;
    for (i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        sprintf(&sha1hash[i*2], "%02x", sha1[i]);
    }
    return sha1hash;
}

char** split_buffer(const char* buffer, int n) {
    int buffer_size = strlen(buffer);
    int part_size = buffer_size / n;
    int remainder = buffer_size % n;

    char** parts = (char**)malloc(n * sizeof(char*));
    if (parts == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    int start = 0;
    int end = 0;

    for (int i = 0; i < n; i++) {
        end += part_size;
        if (i < remainder) {
            end++;  // distribute remainder among first few parts
        }
        parts[i] = (char*)malloc((end - start + 1) * sizeof(char));
        if (parts[i] == NULL) {
            perror("Memory allocation failed");
            exit(EXIT_FAILURE);
        }
        strncpy(parts[i], buffer + start, end - start);
        parts[i][end - start] = '\0'; // Null-terminate the string
        start = end;
    }

    return parts;
}

void HashSetup(CCTK_ARGUMENTS)
{
    // define Cactus variables
    DECLARE_CCTK_ARGUMENTS;
    DECLARE_CCTK_PARAMETERS;

    // get number of processors and my processor number
    int nprocs = CCTK_nProcs(cctkGH);
    int myproc = CCTK_MyProc(cctkGH);

    // open log file
    char* log_filename[100];
    sprintf(log_filename, "hashes_%i.txt", myproc);
    FILE *logfile = fopen(log_filename, "w");
    if (logfile == NULL)
    {
        CCTK_INFO("Error opening file!");
        printf("Error opening file!\n");
        exit(1);
    }

    CCTK_INFO("HashSetup!");

    //print CPU info
    CCTK_VInfo(CCTK_THORNSTRING, "CCTK_nProcs: %i", nprocs);
    fprintf(logfile, "CCTK_nProcs: %i\n", nprocs);
    CCTK_VInfo(CCTK_THORNSTRING, "CCTK_MyProc: %i", myproc);
    fprintf(logfile, "CCTK_MyProc: %i\n", myproc);
    CCTK_VInfo(CCTK_THORNSTRING, "Hello from processor %i", myproc);
    fprintf(logfile, "Hello from processor %i\n", myproc); 

    // Sync grid variables
    int status = CCTK_SyncGroup(cctkGH, "hashlist");
    CCTK_VInfo(CCTK_THORNSTRING, "CCTK_SyncGroup: %i", status);
    fprintf(logfile, "CCTK_SyncGroup: %i\n", status);
    
    // get num grid variables
    int grid_variables = CCTK_NumVars();
    CCTK_VInfo(CCTK_THORNSTRING, "CCTK_NumVars: %i", grid_variables);
    fprintf(logfile, "CCTK_NumVars: %i\n", grid_variables);

    // get num grid groups
    int grid_groups = CCTK_NumGroups();
    CCTK_VInfo(CCTK_THORNSTRING, "CCTK_NumGroups: %i", grid_groups);
    fprintf(logfile, "CCTK_NumGroups: %i\n", grid_groups);

    // get grid variable name for my processor
    char* varname = CCTK_FullVarName(myproc);
    CCTK_VInfo(CCTK_THORNSTRING, "CCTK_VarName: %s", varname);
    fprintf(logfile, "CCTK_VarName: %s\n", varname);

    // get grid variable pointer
    char* var_ptr_hash_dest = CCTK_VarDataPtr(cctkGH, 1, varname);
    CCTK_VInfo(CCTK_THORNSTRING, "CCTK_VarDataPtr: %p", var_ptr_hash_dest);

    // test grid variable pointer
    strdup(var_ptr_hash_dest, "Hello World!");
    CCTK_VInfo(CCTK_THORNSTRING, "CCTK_VarDataPtr: %s", var_ptr_hash_dest);
    fprintf(logfile, "CCTK_VarDataPtr: %s\n", var_ptr_hash_dest);

    // test hash function
    unsigned char* data_string = "Hello World!";
    size_t len = strlen(data_string);
    unsigned char* hash = calculateSHA1(data_string, len);
    char *sha1hash = sha1_to_string(hash);
    CCTK_VInfo(CCTK_THORNSTRING, "Teststring: %s", data_string);
    fprintf(logfile, "Teststring: %s\n", data_string);
    CCTK_VInfo(CCTK_THORNSTRING, "SHA1 HASH: %s\n", sha1hash);
    fprintf(logfile, "SHA1 HASH: %s\n", sha1hash);
    free(hash);
    free(sha1hash);


    // file to hash: /home/lukas/cactus/file_to_hash.txt
    FILE *file_to_hash = fopen(FILE_TO_HASH, "r");
    // get file size
    fseek(file_to_hash, 0, SEEK_END); // seek to end of file
    size_t size = ftell(file_to_hash); // get current file pointer
    fseek(file_to_hash, 0, SEEK_SET); // seek back to beginning of file

    // calculate which part of the file to hash
    size_t part_size = size / nprocs;
    size_t remainder = size % nprocs;
    size_t start = myproc * part_size;
    size_t end = start + part_size;
    CCTK_VInfo(CCTK_THORNSTRING, "File size: %zu", size);
    fprintf(logfile, "File size: %zu\n", size);
    CCTK_VInfo(CCTK_THORNSTRING, "Part size: %zu", part_size);
    fprintf(logfile, "Part size: %zu\n", part_size);
    CCTK_VInfo(CCTK_THORNSTRING, "Start: %zu", start);
    fprintf(logfile, "Start: %zu\n", start);
    CCTK_VInfo(CCTK_THORNSTRING, "End: %zu", end);
    fprintf(logfile, "End: %zu\n", end);

    // read my part of the file
    char* file_buffer = malloc(part_size);
    if (file_buffer == NULL)
    {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    // read the file
    fseek(file_to_hash, start, SEEK_SET);
    fread(file_buffer, 1, part_size, file_to_hash);
    close(file_to_hash);

    // Null-terminate the string
    char* data_to_print = malloc(part_size+1);
    if (data_to_print == NULL)
    {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    strncpy(data_to_print, file_buffer, part_size + 1);

    // //print my file content
    // CCTK_VInfo(CCTK_THORNSTRING, "File content: %s", data_to_print);
    // fprintf(logfile, "File content: %s\n", data_to_print);

    // hash my part of the file
    unsigned char* file_hash = calculateSHA1(file_buffer, part_size);
    char *sha1filehash = sha1_to_string(file_hash);
    CCTK_VInfo(CCTK_THORNSTRING, "SHA1 HASH for part %i: %s\n", myproc, sha1filehash);
    fprintf(logfile, "SHA1 HASH for part %i: %s\n", myproc, sha1filehash);

    // copy hash to grid variable
    int ret = memcpy(var_ptr_hash_dest, file_hash, SHA_DIGEST_LENGTH);
    if (ret == NULL)
    {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }


    // Sync grid variables
    int sync_status = CCTK_SyncGroup(cctkGH, "hashlist");
    CCTK_VInfo(CCTK_THORNSTRING, "CCTK_SyncGroup: %i", sync_status);
    fprintf(logfile, "CCTK_SyncGroup: %i\n", sync_status);

    // free memory
    free(file_buffer);
    free(file_hash);
    // wait for all processors to finish hashing
    CCTK_Barrier(cctkGH);

    // merge hashes on first processor
    if (myproc == 0)
    {
        // merge hashes
        unsigned char* concatenatedHash = malloc(sizeof(char)*SHA_DIGEST_LENGTH*nprocs);
        // go through all grid variables and concatenate hashes
        for (int i = 0; i < nprocs; i++)
        {
            char* get_current_var_name = CCTK_FullVarName(i);
            CCTK_VInfo(CCTK_THORNSTRING, "CCTK_VarName: %s", get_current_var_name);
            fprintf(logfile, "CCTK_VarName: %s\n", get_current_var_name);
            unsigned char* file_hash = (unsigned char*)CCTK_VarDataPtr(cctkGH, 1, get_current_var_name);

            memcpy(concatenatedHash+i*SHA_DIGEST_LENGTH, file_hash, SHA_DIGEST_LENGTH);
        }
        // create final hash
        unsigned char* finalHash = calculateSHA1(concatenatedHash, SHA_DIGEST_LENGTH*nprocs);
        char *sha1hash = sha1_to_string(finalHash);
        CCTK_VInfo(CCTK_THORNSTRING, "FINAL HASH: %s\n", sha1hash);
        fprintf(logfile, "FINAL HASH: %s\n", sha1hash);
        free(concatenatedHash);
        free(finalHash);
        free(sha1hash);
    }

    CCTK_Barrier(cctkGH);

    fclose(logfile);

}

