#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

/*************************
 * BEGIN [my imports and defines]
 *************************/
#include "sgx_tcrypto.h"
#include <stdint.h>

#define DEBUG_PRINT 0
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
    // from https://stackoverflow.com/questions/2376915/how-to-print-out-the-memory-contents-of-a-variable-in-c
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
 * The result calculated will be send back to Alice using OCALLs.
 */
sgx_status_t do_challenge(sgx_aes_ctr_128bit_key_t *p_key, uint8_t *p_ctr_e, uint8_t *p_ctr_d) {
    sgx_status_t sgx_status;
    
    /*************************
     * BEGIN [E_B uses OCALL to receive challenge]
     *************************/
    // Receive the challange
    char *buffer; // pointer to string in untrusted memory that we would get form OCALL
    size_t len;  // length of string
    ocall_recv(&buffer, &len);
    if (len != sizeof(int)*2)
        return SGX_ERROR_UNEXPECTED;
    // copy back value we got
    char rem_ctxt_challenge[len] = {0};
    memcpy(&rem_ctxt_challenge, buffer, len);
    printf("Got ctxt challenge\n");
    /*************************
     * END [E_B uses OCALL to receive challenge]
     *************************/

    /*************************
     * BEGIN [E_B decrypts challenge]
     *************************/
    // Decrypt the challenge ctxt
    char ptxt_challenge[sizeof(int)*2] = {0};
    sgx_status = sgx_aes_ctr_decrypt(p_key, (uint8_t *)rem_ctxt_challenge, len, (uint8_t *)p_ctr_d, 16, (uint8_t *)ptxt_challenge);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_decrypt\n");
        return sgx_status;
    }
    printf("Decrypted challange\n");

    // Now split it back up in the two ints
    int a, b;
    memcpy((char *)&a, ptxt_challenge, sizeof(int));
    memcpy((char *)&b, ptxt_challenge+sizeof(int), sizeof(int));
    /*************************
     * END [E_B decrypts challenge]
     *************************/

    /*************************
     * BEGIN [E_B calculates the challenge result]
     *************************/
    // Do the calculation that Bob does not want to leak
    int c = a + b;
    printf("Result is %x\n", c);
    /*************************
     * END [E_B calculates the challenge result]
     *************************/
    
    /*************************
     * BEGIN [E_B encrypts the challenge result]
     *************************/
    // Encrypt the result and send it back
    char c_ctxt[sizeof(int)] = {0};
    sgx_status = sgx_aes_ctr_encrypt(p_key, (uint8_t *)&c, sizeof(int), (uint8_t *)p_ctr_e, 16, (uint8_t *)c_ctxt);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_encrypt\n");
        return sgx_status;
    }
    /*************************
     * END [E_B encrypts the challenge result]
     *************************/

    /*************************
     * BEGIN [E_B uses OCALL to send challenge result]
     *************************/
    ocall_send((char *)&c_ctxt, sizeof(int));
    printf("Encrypted c and sent\n");
    return SGX_SUCCESS;
    /*************************
     * END [E_B uses OCALL to send challenge result]
     *************************/
}

sgx_status_t run()
{
    // Always check returns
    sgx_status_t sgx_status;

    /*************************
     * BEGIN [E_B created the key pair]
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
    sgx_ec256_public_t p_public_B;
    sgx_status = sgx_ecc256_create_key_pair(&p_private, &p_public_B, ecc_handle);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_ecc256_create_key_pair\n");
        return sgx_status;
    }
    /*************************
     * END [E_B created the key pair]
     *************************/

    /*************************
     * BEGIN [E_B uses OCALL to send the public key to A]
     *************************/
    // send the public key
    size_t size = sizeof(p_public_B);
    ocall_send((char *)&p_public_B, size);
    printf("Sent key \n");
    /*************************
     * END [E_B uses OCALL to send the public key to A]
     *************************/

    /*************************
     * BEGIN [E_B uses OCALL to recv the public key from A]
     *************************/
    // recv (main idea from https://stackoverflow.com/questions/45532406/why-in-sgx-enclave-string-argument-has-to-be-used-with-in-attribute)
    char *buffer; // pointer to string in untrusted memory that we would get form OCALL
    size_t len;  // length of string
    ocall_recv(&buffer, &len);
    // copy back value
    sgx_ec256_public_t p_public_A;
    memcpy(&p_public_A, buffer, len);
    printf("Got key \n");
    /*************************
     * END [E_B uses OCALL to recv the public key from A]
     *************************/

    /*************************
     * BEGIN [E_B computes the shared secret p_shared_key]
     *************************/
    // Use key from B to create dh shared key
    sgx_ec256_dh_shared_t p_shared_key;
    sgx_status = sgx_ecc256_compute_shared_dhkey(&p_private, &p_public_A, &p_shared_key, ecc_handle);
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
     * END [E_B computes the shared secret p_shared_key]
     *************************/

    /*************************
     * BEGIN [E_B encrypts the PSK for itself]
     *************************/
    // Do the handshake part
    sgx_aes_ctr_128bit_key_t p_key;
    // the ptxt
    char *PSK_B = "I AM BOBOB\0";
    // space for the ctxt
    char ctxt[HANDSHAKE_LEN] = {0};
    // keys are saved in little endian, lower 128 bit are the first 16 B of it
    //printf("Sizeof sgx_aes_ctr_128bit_key_t: %ld\n", sizeof(p_key));
    memcpy(&p_key, &p_shared_key, sizeof(p_key));
    //print_mem_content((unsigned char *)p_key, 16);
    // the IV    
    uint8_t p_ctr_e[16];
    memset(p_ctr_e, 0, 16);
    sgx_status = sgx_aes_ctr_encrypt(&p_key, (uint8_t *)PSK_B, HANDSHAKE_LEN, (uint8_t *)p_ctr_e, 1, (uint8_t *)ctxt);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_encrypt\n");
        return sgx_status;
    }
    printf("Encrypted PSK success\n");
    /*************************
     * END [E_B encrypts the PSK for itself]
     *************************/

    /*************************
     * BEGIN [E_B sends the encrypted PSK using the OCALL]
     *************************/
    // Now send this PSK
    size = HANDSHAKE_LEN;
    ocall_send(ctxt, size);
    printf("Send out PSK: %s\n", PSK_B);
    /*************************
     * END [E_B sends the encrypted PSK using the OCALL]
     *************************/

    /*************************
     * BEGIN [E_B receives the encrypted PSK of A using the OCALL]
     *************************/
    // Receive the PSK from the other party and checks it's size
    ocall_recv(&buffer, &len);
    if (len != HANDSHAKE_LEN)
        return SGX_ERROR_UNEXPECTED;
    // copy back value we got
    char rem_ctxt[len] = {0};
    memcpy(&rem_ctxt, buffer, len);
    printf("Got remote PSK\n");
    /*************************
     * END [E_B receives the encrypted PSK of A using the OCALL]
     *************************/

    /*************************
     * BEGIN [E_B decrypts the remote PSK]
     *************************/
    // Decode the remote PSK and check it is correct size
    char PSK_A[HANDSHAKE_LEN] = {0};
    uint8_t p_ctr_d[16];
    memset(p_ctr_d, 0, 16);
    sgx_status = sgx_aes_ctr_decrypt(&p_key, (uint8_t *)rem_ctxt, HANDSHAKE_LEN, (uint8_t *)p_ctr_d, 16, (uint8_t *)PSK_A);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_decrypt\n");
        return sgx_status;
    }
    printf("Got remote PSK decrypted: %s\n", PSK_A);
    /*************************
     * END [E_B decrypts the remote PSK]
     *************************/

    /*************************
     * BEGIN [E_B does the checkPSK]
     *************************/
    // Check against what we expect from the other side
    if (strncmp("I AM ALICE", PSK_A, HANDSHAKE_LEN) != 0) {
        printf("The PSK is not the expected one!\n");
        // TODO split this part off into a seperate ECALL
        return SGX_ERROR_UNEXPECTED;
    }
    /*************************
     * END [E_B does the checkPSK]
     *************************/

    /*************************
     * BEGIN [doing the challenge 20 times]
     *************************/
    // Do the whole thing 20 times
    for (int i = 1; i < 21; i++) {
        sgx_status = do_challenge(&p_key, p_ctr_e, p_ctr_d);
        if (sgx_status != SGX_SUCCESS) {
            printf("Errored out at do_challenge\n");
            return sgx_status;
        }
        printf("Nice, we sent c! (%d)\n", i);
    }
    /*************************
     * END [doing the challenge 20 times]
     *************************/
    return SGX_SUCCESS;
}
