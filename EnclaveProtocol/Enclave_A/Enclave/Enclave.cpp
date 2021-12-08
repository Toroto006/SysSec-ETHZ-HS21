#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

/*************************
 * BEGIN [my imports and defines]
 *************************/
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"

// If the enclave should do any debug output!
#define DEBUG_PRINT 0

// The text for the MAC
char aad_mac_text[BUFSIZ] = "ALICE MAC text";
/*************************
 * END [my imports and defines]
 *************************/

/*************************
 * BEGIN [enclave part of printf OCALL]
 *************************/
/*
 * Function: printf
 * ----------------------------
 * Nothing more than an OCALL to printf in the app (used for debugging)
 * If DEBUG_PRINT is False then this will do nothing more than return
 * the length of the string that would have been printed. 
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    if (DEBUG_PRINT)
        ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}
/*************************
 * END [enclave part of printf OCALL]
 *************************/

/*************************
 * BEGIN [enclave print_mem_content calling printf OCALL]
 *************************/
/*
 * Function: print_mem_content
 * ----------------------------
 * This function takes as input a pointer to memory and a size of
 * how many bytes from that memory it should output in hex encoding.
 * Based on https://stackoverflow.com/questions/2376915/how-to-print-out-the-memory-contents-of-a-variable-in-c
 * (was used for debugging)
 */
void print_mem_content(unsigned char *p, size_t size){
    for (long unsigned int i = 0; i < size; i++)
        printf("%02x ", p[i]);
    printf("\n");
}
/*************************
 * END [enclave print_mem_content calling printf OCALL]
 *************************/

/*
 * Function: do_challenge
 * ----------------------------
 * This function will do a single challenge run given the enryption key,
 * encryption and decryption IV.
 * The result if Bob did the calculation of the numbers correctly
 * will be written to the correct value.
 */
sgx_status_t do_challenge(sgx_aes_ctr_128bit_key_t *p_key, uint8_t *p_ctr_e, uint8_t *p_ctr_d, int *correct){
    sgx_status_t sgx_status;
    /*************************
     * BEGIN [E_A generates challenge]
     *************************/
    // Create space for the two numbers
    int a, b;
    // create random number a and b
    sgx_status = sgx_read_rand((unsigned char*)&a, sizeof(int));
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_read_rand\n");
        return sgx_status;
    }
    sgx_status = sgx_read_rand((unsigned char*)&b, sizeof(int));
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_read_rand\n");
        return sgx_status;
    }
    printf("Created two random numbers a: %x and b: %x\n", a, b);

    // Now we create the a||b to send
    char ptxt_challenge[sizeof(int)*2] = {0};
    memcpy(ptxt_challenge, (char *)&a, sizeof(int));
    memcpy(ptxt_challenge+sizeof(int), (char *)&b, sizeof(int));
    /*************************
     * END [E_A generates challenge]
     *************************/
    /*************************
     * BEGIN [E_A encrypts challenge]
     *************************/
    // Encrypt the challenge message after creating space for the encrypted one
    char ctxt_challenge[sizeof(int)*2] = {0};
    sgx_status = sgx_aes_ctr_encrypt(p_key, (uint8_t *)ptxt_challenge, sizeof(int)*2, (uint8_t *)p_ctr_e, 16, (uint8_t *)ctxt_challenge);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_encrypt\n");
        return sgx_status;
    }
    /*************************
     * END [E_A encrypts challenge]
     *************************/

    /*************************
     * BEGIN [E_A uses OCALL to send challenge using App A]
     *************************/
    // Send the encrypted message
    ocall_send((char *)&ctxt_challenge, sizeof(int)*2);
    printf("Sent challenge\n");
    /*************************
     * END [E_A uses OCALL to send challenge using App A]
     *************************/

    /*************************
     * BEGIN [E_A uses OCALL to recv challenge result]
     *************************/
    // Receive the response from Bob for cs
    char *buffer; // pointer to string in untrusted memory that we would get form OCALL
    size_t len;  // length of string
    ocall_recv(&buffer, &len);
    if (len != sizeof(int))
        return SGX_ERROR_UNEXPECTED;
    // copy back value we got
    char c_ctxt[len] = {0};
    memcpy(&c_ctxt, buffer, len);
    /*************************
     * END [E_A uses OCALL to recv challenge result]
     *************************/

    /*************************
     * BEGIN [E_A decrypts challenge result]
     *************************/
    // Now do the decryption
    int c_recv = 0;
    sgx_status = sgx_aes_ctr_decrypt(p_key, (uint8_t *)c_ctxt, len, (uint8_t *)p_ctr_d, 16, (uint8_t *)&c_recv);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_decrypt\n");
        return sgx_status;
    }
    printf("Got remote c\n");
    /*************************
     * END [E_A decrypts challenge result]
     *************************/

    /*************************
     * BEGIN [E_A verifies the challenge results]
     *************************/
    // Do the calculation Alice just figured out
    int c = a + b;
    // Do check of equivalence
    printf("Results are %x for c and %x c_recv\n", c, c_recv);
    *correct = c == c_recv;
    return SGX_SUCCESS;
    /*************************
     * END [E_A verifies the challenge results]
     *************************/
}

/*
 * Function: get_sealed_data_size
 * ----------------------------
 * returns the size of the sealed key in uint32_t
 */
uint32_t get_sealed_size()
{
    sgx_ec256_dh_shared_t p_shared_key;
    printf("Size shared key: %ld", sizeof(p_shared_key));
    return sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t) sizeof(p_shared_key));
}

/*************************
 * BEGIN [E_A function to seal shared key]
 *************************/
/*
 * Function: seal_key
 * ----------------------------
 * takes as input the shared key and seals it
 */
sgx_status_t seal_key(uint8_t* sealed_key, uint32_t data_size, sgx_ec256_dh_shared_t *p_shared_key) {
    // To use size of
    sgx_ec256_dh_shared_t dh_key;

    uint32_t sealed_data_size = get_sealed_size();
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    sgx_status_t  err = sgx_seal_data((uint32_t)strlen(aad_mac_text), (const uint8_t *)aad_mac_text, 
        (uint32_t) sizeof(dh_key), (uint8_t *)p_shared_key, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        // Copy the sealed data to outside buffer
        memcpy(sealed_key, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}
/*************************
 * END [E_A function to seal shared key]
 *************************/

/*************************
 * BEGIN [E_A function to unseal shared key]
 *************************/
/*
 * Function: unseal_key
 * ----------------------------
 * takes as input the sealed key and unseals it
 */
sgx_status_t unseal_key(const uint8_t *sealed_key, size_t data_size, sgx_ec256_dh_shared_t *p_shared_key) {
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_key);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_key);
    if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if(mac_text_len > data_size || decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *de_mac_text =(uint8_t *)malloc(mac_text_len);
    if(de_mac_text == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    if(decrypt_data == NULL)
    {
        free(de_mac_text);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_key, de_mac_text, &mac_text_len, decrypt_data, &decrypt_data_len);
    if (ret != SGX_SUCCESS)
    {
        free(de_mac_text);
        free(decrypt_data);
        return ret;
    }

    // Check the MAC is okay
    if (memcmp(de_mac_text, aad_mac_text, strlen(aad_mac_text)))
    {
        free(de_mac_text);
        free(decrypt_data);
        return SGX_ERROR_UNEXPECTED;
    }

    // If so write the shared key
    memcpy(p_shared_key, decrypt_data, decrypt_data_len);

    free(de_mac_text);
    free(decrypt_data);
    return ret;
}
/*************************
 * END [E_A function to unseal shared key]
 *************************/

sgx_status_t createEnclave(uint8_t* sealed_key, uint32_t data_size) {
    // Always check returns
    sgx_status_t sgx_status;
    /*************************
     * BEGIN [E_A created the key pair]
     *************************/
    // Create ECC context
    sgx_ecc_state_handle_t ecc_handle;
    sgx_status = sgx_ecc256_open_context(&ecc_handle);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_ecc256_open_context\n");
        return sgx_status;
    }
    printf("Was able to open ECC context\n");
    // Create key
    sgx_ec256_private_t p_private;
    sgx_ec256_public_t p_public_A;
    sgx_status = sgx_ecc256_create_key_pair(&p_private, &p_public_A, ecc_handle);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_ecc256_create_key_pair\n");
        return sgx_status;
    }
    /*************************
     * END [E_A created the key pair]
     *************************/

    /*************************
     * BEGIN [E_A uses OCALL to send the public key to B]
     *************************/
    // send
    size_t size = sizeof(p_public_A);
    ocall_send((char *)&p_public_A, size);
    printf("Sent public key\n");
    /*************************
     * END [E_A uses OCALL to send the public key to B]
     *************************/

    /*************************
     * BEGIN [E_A uses OCALL to recv the public key from B]
     *************************/
    // recv (main idea from https://stackoverflow.com/questions/45532406/why-in-sgx-enclave-string-argument-has-to-be-used-with-in-attribute)
    char *buffer; // pointer to string in untrusted memory that we would get form OCALL
    size_t len;  // length of string
    ocall_recv(&buffer, &len);
    // copy back value we got
    sgx_ec256_public_t p_public_B;
    memcpy(&p_public_B, buffer, len);
    printf("Got public key\n");
    /*************************
     * END [E_A uses OCALL to recv the public key from B]
     *************************/

    /*************************
     * BEGIN [E_A computes the shared secret p_shared_key]
     *************************/
    // Use key from B to create dh shared key
    sgx_ec256_dh_shared_t p_shared_key;
    sgx_status = sgx_ecc256_compute_shared_dhkey(&p_private, &p_public_B, &p_shared_key, ecc_handle);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_ecc256_compute_shared_dhkey\n");
        return sgx_status;
    }
    printf("Shared key created!\n");
    
    // Cleanup the ecc stuff
    sgx_status = sgx_ecc256_close_context(ecc_handle);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_ecc256_close_context\n");
        return sgx_status;
    }
    /*************************
     * END [E_A computes the shared secret p_shared_key]
     *************************/

    /*************************
     * BEGIN [E_A seals the shared key to be used later]
     *************************/
    // Return the shared key as sealed data
    sgx_status = seal_key(sealed_key, data_size, &p_shared_key);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at seal_key\n");
        return sgx_status;
    }
    /*************************
     * END [E_A seals the shared key to be used later]
     *************************/
    return SGX_SUCCESS;
}

/*
 * Function: getPSK
 * ----------------------------
 * will do the handshake and fail if the PSK was not successful
 */
sgx_status_t getPSK(const uint8_t *sealed_key, size_t data_size) {
    // Always check returns
    sgx_status_t sgx_status;

    // unseal the shared key
    sgx_ec256_dh_shared_t p_shared_key;
    sgx_status = unseal_key(sealed_key, data_size, &p_shared_key);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at unseal_key\n");
        return sgx_status;
    }

    /*************************
     * BEGIN [E_A encrypts the PSK for itself]
     *************************/
    // Do the handshake part
    sgx_aes_ctr_128bit_key_t p_key;
    // the ptxt
    char *PSK_A = "I AM ALICE\0";
    // space for the ctxt
    char ctxt[HANDSHAKE_LEN] = {0};
    // keys are saved in little endian, lower 128 bit are the first 16 B of it
    memcpy(&p_key, &p_shared_key, sizeof(p_key));
    //print_mem_content((unsigned char *)p_key, 16);
    // the IV
    uint8_t p_ctr_e[16];
    memset(p_ctr_e, 0, 16);
    sgx_status = sgx_aes_ctr_encrypt(&p_key, (uint8_t *)PSK_A, HANDSHAKE_LEN, (uint8_t *)p_ctr_e, 16, (uint8_t *)ctxt);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_encrypt\n");
        return sgx_status;
    }
    printf("Encrypted PSK success\n");
    /*************************
     * END [E_A encrypts the PSK for itself]
     *************************/

    /*************************
     * BEGIN [E_A sends the encrypted PSK using the OCALL]
     *************************/
    // Now send this PSK
    ocall_send(ctxt, HANDSHAKE_LEN);
    printf("Send out PSK: %s\n", PSK_A);
    /*************************
     * END [E_A sends the encrypted PSK using the OCALL]
     *************************/

    /*************************
     * BEGIN [E_A receives the encrypted PSK of B using the OCALL]
     *************************/
    // Receive the PSK from the other party
    char *buffer; // pointer to string in untrusted memory that we would get form OCALL
    size_t len;  // length of strings
    ocall_recv(&buffer, &len);
    if (len != HANDSHAKE_LEN)
        return SGX_ERROR_UNEXPECTED;
    // copy back value we got
    char rem_ctxt[len] = {0};
    memcpy(&rem_ctxt, buffer, len);
    printf("Got remote PSK:\n");
    /*************************
     * END [E_A receives the encrypted PSK of B using the OCALL]
     *************************/
    
    /*************************
     * BEGIN [E_A decrypts the remote PSK]
     *************************/
    // Decode the remote PSK and check it is correct size
    char PSK_B[HANDSHAKE_LEN] = {0};
    uint8_t p_ctr_d[16];
    memset(p_ctr_d, 0, 16);
    sgx_status = sgx_aes_ctr_decrypt(&p_key, (uint8_t *)rem_ctxt, HANDSHAKE_LEN, (uint8_t *)p_ctr_d, 16, (uint8_t *)PSK_B);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_decrypt\n");
        return sgx_status;
    }
    printf("Got remote PSK decrypted: %s\n", PSK_B);
    /*************************
     * END [E_A decrypts the remote PSK]
     *************************/

    /*************************
     * BEGIN [E_A does the checkPSK]
     *************************/
    // Check against what we expect from the other side
    if (strncmp("I AM BOBOB", PSK_B, HANDSHAKE_LEN) != 0) {
        printf("The PSK is not the expected one!\n");
        return SGX_ERROR_UNEXPECTED;
    }
    /*************************
     * END [E_A does the checkPSK]
     *************************/
    return SGX_SUCCESS;
}

/*************************
 * BEGIN [E_A wrapper around do_challenge]
 *************************/
/*
 * Function: getChallenge
 * ----------------------------
 * Is a wrapper around the do_challenge unsealing
 * the shared key and adjusting the IVs
 */
sgx_status_t getChallenge(const uint8_t *sealed_key, size_t data_size, int iteration, int *success) {
    // Always check returns
    sgx_status_t sgx_status;

    // unseal the shared key
    sgx_ec256_dh_shared_t p_shared_key;
    sgx_status = unseal_key(sealed_key, data_size, &p_shared_key);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at unseal_key\n");
        return sgx_status;
    }
    // Do the handshake part
    sgx_aes_ctr_128bit_key_t p_key;
    // keys are saved in little endian, lower 128 bit are the first 16 B of it
    memcpy(&p_key, &p_shared_key, sizeof(p_key));

    // Now that we know we talk to Bob and have the shared key again
    // For that we need the IV counter
    uint8_t p_ctr_e[16];
    uint8_t p_ctr_d[16];
    memset(p_ctr_e, 0, 16);
    memset(p_ctr_d, 0, 16);
    // Set it to the correct iteration (20 are within single byte)
    p_ctr_e[15] = (uint8_t) iteration;
    p_ctr_d[15] = (uint8_t) iteration;

    // let's do the actual task
    sgx_status = do_challenge(&p_key, p_ctr_e, p_ctr_d, success);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at do_challenge\n");
        return sgx_status;
    }

    return SGX_SUCCESS;
}
/*************************
 * END [E_A wrapper around do_challenge]
 *************************/