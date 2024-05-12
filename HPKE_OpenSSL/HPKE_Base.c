#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <openssl/hpke.h>
#include <openssl/evp.h>
#include <time.h>
#include <stdbool.h>
#include "cJSON.h"

#define LBUFSIZE 100

// Function used to convert an exadecimal string to a bytes string (same as bytes.fromhex() in Python)
unsigned char* bytes_from_hex(const char *hex_string, size_t *output_length) {
    size_t length = strlen(hex_string);
    *output_length = length / 2;
    unsigned char *result = (unsigned char*)malloc(*output_length);

    if (length % 2 != 0) {
        fprintf(stderr, "The exadecimal string must have an even length\n");
        return NULL;
    }
    
    if (result == NULL) {
        fprintf(stderr, "Error in memory allocation\n");
        return NULL;
    }

    for (size_t i = 0; i < *output_length; ++i) {
        sscanf(hex_string + 2 * i, "%2hhx", &result[i]);
    }

    return result;
}

// Function used to convert an exadecimal string to a bytes array, needed for the ikm
void bytes_array_from_hex(const char *hex_string, const unsigned char *bytes) {
    size_t len = strlen(hex_string);
    size_t byte_length = len / 2;

    for (size_t i = 0; i < byte_length; ++i) {
        sscanf(&hex_string[i * 2], "%2hhx", &bytes[i]);
    }
}

int main(int argc, char **argv)
{   
    clock_t start, end;
    double total_time;
    int n_repeat = 10000;        // N° of times the experiment must be performed for each mode
    bool pre_shared = false;    // Used to check if the mode is a pre-shared key one
    bool auth = false;          // Used to check if the mode is an authenticated one
    bool print_on = true;       // Print enabled only for the first cicle

    // Retrive the content of the JSON file and we store it in a variable
    FILE *file = fopen("test_vectors.json", "r");
    if(!file){
        printf("Impossibile aprire il file JSON");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *jsonData = (char *)malloc(file_size + 1);
    fread(jsonData, 1, file_size, file);
    fclose(file);

    // Puts the extracted content back in JSON format
    cJSON *json = cJSON_Parse(jsonData);
    if(!json){
        printf("Error in JSON parsing \n");
        free(jsonData);
        return 1;
    }

    for (int i = 1; i <=4; i++){
        for(int j = 1; j <= n_repeat; j++){
            char i_value[20];
            sprintf(i_value, "%d", i);
            char test_name[10] = "test";
            strcat(test_name, i_value);

            // Retrive test object from the JSON
            cJSON *test = cJSON_GetObjectItem(json, test_name);
            if(test == NULL || !cJSON_IsObject(test)){
                printf("Error in retriving the object \n");
                cJSON_Delete(json);
                return 1;
            }
            
            // Extract all the data from test_vectors in the correct format
            cJSON *mode = cJSON_GetObjectItem(test, "mode");
            if(mode == NULL || !cJSON_IsNumber(mode)){
                printf("Error in retriving the HPKE mode \n");
                cJSON_Delete(json);
                return 1;
            }else{
                if(print_on)
                    printf("Mode: %d\n", mode -> valueint);
            }

            cJSON *kemID = cJSON_GetObjectItem(test, "kem_id");
            if(kemID == NULL || !cJSON_IsNumber(kemID)){
                kemID = cJSON_CreateNumber(16);
            }

            cJSON *kdfID = cJSON_GetObjectItem(test, "kdf_id");
            if(kdfID == NULL || !cJSON_IsNumber(kdfID)){
                kdfID = cJSON_CreateNumber(1);
            }

            cJSON *aeadID = cJSON_GetObjectItem(test, "aead_id");
            if(aeadID == NULL || !cJSON_IsNumber(aeadID)){
                aeadID = cJSON_CreateNumber(3);
            }

            size_t output_length;
            cJSON *get_pt = cJSON_GetObjectItem(test, "pt");
            if(get_pt == NULL || !cJSON_IsString(get_pt)){
                get_pt = cJSON_CreateString("");
            }
            const unsigned char pt[strlen(get_pt -> valuestring) / 2];
            bytes_array_from_hex(get_pt -> valuestring, pt);
            size_t pt_len = strlen((char *) pt);

            cJSON *get_ct = cJSON_GetObjectItem(test, "ct");
            if(get_ct == NULL || !cJSON_IsString(get_ct)){
                get_ct = cJSON_CreateString("");
            }
            const unsigned char ct[strlen(get_ct -> valuestring) / 2];
            bytes_array_from_hex(get_ct -> valuestring, ct);

            cJSON *get_info = cJSON_GetObjectItem(test, "info");
            if(get_info == NULL || !cJSON_IsString(get_info)){
                get_info = cJSON_CreateString("");
            }
            const unsigned char info[strlen(get_info -> valuestring) / 2];
            bytes_array_from_hex(get_info -> valuestring, info);
            size_t info_len = sizeof(info);

            cJSON *get_aad = cJSON_GetObjectItem(test, "aad");
            if(get_aad == NULL || !cJSON_IsString(get_aad)){
                get_aad = cJSON_CreateString("");
            }
            const unsigned char aad[strlen(get_aad -> valuestring) / 2];
            bytes_array_from_hex(get_aad -> valuestring, aad);
            size_t aad_len = sizeof(aad);

            cJSON *get_enc = cJSON_GetObjectItem(test, "enc");
            if(get_enc == NULL || !cJSON_IsString(get_enc)){
                get_enc = cJSON_CreateString("");
            }
            const unsigned char enc_key[strlen(get_enc -> valuestring) / 2];
            bytes_array_from_hex(get_enc -> valuestring, enc_key);

            cJSON *get_psk = cJSON_GetObjectItem(test, "psk");
            if(get_psk == NULL || !cJSON_IsString(get_psk)){
                get_psk = cJSON_CreateString("");
            }else{
                pre_shared = true;
            }
            const unsigned char psk[strlen(get_psk -> valuestring) / 2];
            bytes_array_from_hex(get_psk -> valuestring, psk);
            size_t psk_len = sizeof(psk);

            cJSON *get_psk_id = cJSON_GetObjectItem(test, "psk_id");
            if(get_psk_id == NULL || !cJSON_IsString(get_psk_id)){
                get_psk_id = cJSON_CreateString("");
            }
            const unsigned char psk_id[strlen(get_psk_id -> valuestring) / 2];
            bytes_array_from_hex(get_psk_id -> valuestring, psk_id);

            cJSON *get_pkr = cJSON_GetObjectItem(test, "pkRm");
            if(get_pkr == NULL || !cJSON_IsString(get_pkr)){
                get_pkr = cJSON_CreateString("");
            }
            const unsigned char pkr_key[strlen(get_pkr -> valuestring) / 2];
            bytes_array_from_hex(get_pkr -> valuestring, pkr_key);

            cJSON *get_ikmR = cJSON_GetObjectItem(test, "ikmR");
            if(get_ikmR == NULL || !cJSON_IsString(get_ikmR)){
                get_ikmR = cJSON_CreateString("");
            }
            const unsigned char ikmR[strlen(get_ikmR -> valuestring) / 2];
            bytes_array_from_hex(get_ikmR -> valuestring, ikmR);
            size_t ikmR_len = sizeof(ikmR);

            cJSON *get_ikmE = cJSON_GetObjectItem(test, "ikmE");
            if(get_ikmE == NULL || !cJSON_IsString(get_ikmE)){
                get_ikmE = cJSON_CreateString("");
            }
            const unsigned char ikmE[strlen(get_ikmE -> valuestring) / 2];
            bytes_array_from_hex(get_ikmE -> valuestring, ikmE);
            size_t ikmE_len = sizeof(ikmE);

            // Retrive the sender keys, only if they are present, depending on the mode
            cJSON *get_ikmS = cJSON_GetObjectItem(test, "ikmS");
            if(get_ikmS != NULL){
                auth = true;
            }else{
                get_ikmS = cJSON_CreateString("");
            }
            const unsigned char ikmS[strlen(get_ikmS -> valuestring) / 2];
            if(auth){
                bytes_array_from_hex(get_ikmS -> valuestring, ikmS);
            }
            size_t ikmS_len = sizeof(ikmS);

            OSSL_HPKE_CTX *sctx = NULL, *rctx = NULL;
            
            EVP_PKEY *sks = NULL;          // Sender private key
            unsigned char pks[LBUFSIZE];    // Sender public key
            size_t pkslen = sizeof(pks);

            EVP_PKEY *skr = NULL;          // Receiver private key
            unsigned char pkr[LBUFSIZE];    // Receiver public key
            size_t pkrlen = sizeof(pkr);

            unsigned char enc[LBUFSIZE];    // Encapsulated public sender value
            size_t enclen = sizeof(enc);

            unsigned char ciphertext[LBUFSIZE];
            size_t ciphertext_len = sizeof(ciphertext);
            unsigned char plaintext[LBUFSIZE];
            size_t plaintext_len = sizeof(plaintext);

            start = clock();

            // Create the suite, a structure that holds identifiers for the algorithms used for KEM, KDF and AEAD operations
            OSSL_HPKE_SUITE suite = {kemID-> valueint, kdfID-> valueint, aeadID-> valueint};

            // Generate sender's key pair, only if mode is an authenticated one
            if(auth){
                if (OSSL_HPKE_keygen(suite, pks, &pkslen, &sks, ikmS, ikmS_len, NULL, NULL) != 1){
                    printf("Error in key generation\n");
                    return 1;
                }
            }
            
            // Generate receiver's key pair. The receiver will give this public key to the sender
            if (OSSL_HPKE_keygen(suite, pkr, &pkrlen, &skr, ikmR, ikmR_len, NULL, NULL) != 1){
                printf("Error in key generation\n");
                return 1;
            }

            // Create the context, that maintains internal state as HPKE operations are carried out
            // Separated context must be used for the sender and receiver
            if ((sctx = OSSL_HPKE_CTX_new(mode->valueint, suite, OSSL_HPKE_ROLE_SENDER, NULL, NULL)) == NULL){
                printf("Error in sender context creation\n");
                return 1;
            }

            OSSL_HPKE_CTX_set1_ikme(sctx, ikmE, ikmE_len);  // Allows the user to generate senders ephemeral private key by setting a deterministic ikm

            if(auth){
                OSSL_HPKE_CTX_set1_authpriv(sctx, sks);     // Used by the sender to set its private key
            }
            if(pre_shared){
                OSSL_HPKE_CTX_set1_psk(sctx, (char *) psk_id, psk, psk_len);
            }

            // Sender encrypt to encapsulate sender's public value in enc, using the receiver public key and the info
            if (OSSL_HPKE_encap(sctx, enc, &enclen, pkr, pkrlen, info, info_len) != 1){
                printf("Error in encap\n");
                return 1;
            }

            if(print_on && strcmp((char *) enc_key, (char *) enc) != 0){      // Check if the enc generated is the same present in the test_vectors
                printf("Different enc\n");                                    // Its different because OpenSSL add to the enc some bytes used internally
            }                                                                 // such as initialization vectors or some metadata or formatting informations

            if (OSSL_HPKE_seal(sctx, ciphertext, &ciphertext_len, aad, aad_len, pt, pt_len) != 1){      // Sealing the plaintext using the aad
                printf("Error in seal\n");
                return 1;
            }
            
            if(print_on && strcmp((char *) ct, (char *) ciphertext) != 0){    // Check if the ciphertext generated is the same present in the test_vectors
                printf("Different ciphertext\n");
            }
            
            if ((rctx = OSSL_HPKE_CTX_new(mode->valueint, suite, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL)) == NULL){
                printf("Error in receiver context creation\n");
                return 1;
            }

            if(auth)
                OSSL_HPKE_CTX_set1_authpub(rctx, pks, pkslen);      // Used by the receiver to set the sender public key
            if(pre_shared)
                OSSL_HPKE_CTX_set1_psk(rctx, (char *) psk_id, psk, psk_len);

            // Receiver decrypt data using its private key 
            if (OSSL_HPKE_decap(rctx, enc, enclen, skr, info, info_len) != 1){
                printf("Error in decap\n");
                return 1;
            }

            if (OSSL_HPKE_open(rctx, plaintext, &plaintext_len, aad, aad_len, ciphertext, ciphertext_len) != 1){
                printf("Error in open\n");
                return 1;
            }

            // Print deciphered text
            if(print_on){
                printf("Original plaintext: %s\n", pt);
                printf("Deciphered plaintext: %.*s\n", (int)sizeof(plaintext), plaintext);
                if(strcmp((char *) pt, (char *)plaintext) != 0){
                    printf("Error in decryption\n");
                }
            }

            end = clock();
            total_time += ((double) (end - start)) / (CLOCKS_PER_SEC / 1000);

            // Free the memory
            OSSL_HPKE_CTX_free(rctx);
            OSSL_HPKE_CTX_free(sctx);
            EVP_PKEY_free(skr);
            EVP_PKEY_free(sks);
            auth = false;
            pre_shared = false;
            print_on = false;
        }
        printf("Total execution time in milliseconds: %f\n", total_time/n_repeat);      // We do a mean of the execution time registered at each iteration
        printf("\n");
        total_time = 0;
        print_on = true;
    }
    cJSON_Delete(json);
    free(jsonData);
    
    return 0;
}

