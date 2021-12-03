#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

// My imports
#include "sgx_trts.h"
#include "sgx_tcrypto.h"

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void print_mem_content(unsigned char *p, size_t size){
    // from https://stackoverflow.com/questions/2376915/how-to-print-out-the-memory-contents-of-a-variable-in-c
    for (long unsigned int i = 0; i < size; i++)
        printf("%02x ", p[i]);
    printf("\n");
}

sgx_status_t do_challenge(sgx_aes_ctr_128bit_key_t *p_key, uint128_t p_ctr_e, uint128_t p_ctr_d, int *correct){
        // TODO split out to seperate ECALL
    sgx_status_t sgx_status;
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
    
    // Encrypt the challenge message after creating space for the encrypted one
    char ctxt_challenge[sizeof(int)*2] = {0};
    sgx_status = sgx_aes_ctr_encrypt(p_key, (uint8_t *)ptxt_challenge, sizeof(int)*2, (uint8_t *)&p_ctr_e, 16, (uint8_t *)ctxt_challenge);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_encrypt\n");
        return sgx_status;
    }

    // Send the encrypted message
    ocall_send((char *)&ctxt_challenge, sizeof(int)*2);
    printf("Sent challenge\n");

    // Do the calculation Alice just figured out
    int c = a + b;

    // Receive the response from Bob for cs
    char *buffer; // pointer to string in untrusted memory that we would get form OCALL
    size_t len;  // length of string
    ocall_recv(&buffer, &len);
    if (len != sizeof(int))
        return SGX_ERROR_UNEXPECTED;
    // copy back value we got
    char c_ctxt[len] = {0};
    memcpy(&c_ctxt, buffer, len);
    //print_mem_content((unsigned char *)c_ctxt, len);

    // Now do the decryption
    int c_recv = 0;
    sgx_status = sgx_aes_ctr_decrypt(p_key, (uint8_t *)c_ctxt, len, (uint8_t *)&p_ctr_d, 16, (uint8_t *)&c_recv);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_decrypt\n");
        return sgx_status;
    }
    printf("Got remote c\n");

    // Do check of equivalence
    printf("Results are %x for c and %x c_recv\n", c, c_recv);
    *correct = c != c_recv;
    return SGX_SUCCESS;
}

sgx_status_t run()
{
    // Always check returns
    sgx_status_t sgx_status;

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
    //printf("size key: %ld\n", sizeof(p_public));

    // send
    size_t size = sizeof(p_public_A);
    ocall_send((char *)&p_public_A, size);
    printf("Sent public key\n");

    // recv (main idea from https://stackoverflow.com/questions/45532406/why-in-sgx-enclave-string-argument-has-to-be-used-with-in-attribute)
    char *buffer; // pointer to string in untrusted memory that we would get form OCALL
    size_t len;  // length of string
    ocall_recv(&buffer, &len);
    // copy back value we got
    sgx_ec256_public_t p_public_B;
    memcpy(&p_public_B, buffer, len);
    printf("Got public key\n");

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

    // Do the handshake part
    sgx_aes_ctr_128bit_key_t p_key;
    // the ptxt
    char *PSK_A = "I AM ALICE\0";
    // space for the ctxt
    char ctxt[HANDSHAKE_LEN] = {0};
    // keys are saved in little endian, lower 128 bit are the first 16 B of it
    //printf("Sizeof sgx_aes_ctr_128bit_key_t: %ld\n", sizeof(p_key));
    memcpy(&p_key, &p_shared_key, sizeof(p_key));
    //print_mem_content((unsigned char *)p_key, 16);
    // the IV
    uint128_t p_ctr_e = 0;
    sgx_status = sgx_aes_ctr_encrypt(&p_key, (uint8_t *)PSK_A, HANDSHAKE_LEN, (uint8_t *)&p_ctr_e, 16, (uint8_t *)ctxt);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_encrypt\n");
        return sgx_status;
    }
    printf("Encrypted PSK success\n");
    //print_mem_content((unsigned char *)ctxt, HANDSHAKE_LEN);

    // Now send this PSK
    ocall_send(ctxt, HANDSHAKE_LEN);
    printf("Send out PSK: %s\n", PSK_A);

    // Receive the PSK from the other party
    ocall_recv(&buffer, &len);
    if (len != HANDSHAKE_LEN)
        return SGX_ERROR_UNEXPECTED;
    // copy back value we got
    char rem_ctxt[len] = {0};
    memcpy(&rem_ctxt, buffer, len);
    printf("Got remote PSK:\n");
    // Decode the remote PSK and check it is correct size
    char PSK_B[HANDSHAKE_LEN] = {0};
    uint128_t p_ctr_d = 0;
    sgx_status = sgx_aes_ctr_decrypt(&p_key, (uint8_t *)rem_ctxt, HANDSHAKE_LEN, (uint8_t *)&p_ctr_d, 16, (uint8_t *)PSK_B);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_decrypt\n");
        return sgx_status;
    }
    printf("Got remote PSK decrypted: %s\n", PSK_B);
    // Check against what we expect from the other side
    if (strncmp("I AM BOBOB", PSK_B, HANDSHAKE_LEN) != 0) {
        printf("The PSK is not the expected one!\n");
        // TODO split this part off into a seperate ECALL
        return SGX_ERROR_UNEXPECTED;
    }

    // Now that we know we talk to Bob let's do the actual task
    // Do the whole thing 20 times
    int correct;
    for (int i = 1; i < 21; i++) {
        sgx_status = do_challenge(&p_key, p_ctr_e, p_ctr_d, &correct);
        if (sgx_status != SGX_SUCCESS) {
            printf("Errored out at do_challenge\n");
            return sgx_status;
        }
        if (correct) {
            printf("Bob was not able to calculate the result c correctly!!");
            return SGX_ERROR_UNEXPECTED;
        }
        printf("Nice, Bob did it! (%d)\n", i);
    }
    // No cleanup to do?
    return SGX_SUCCESS;
}
