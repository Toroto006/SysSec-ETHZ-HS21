#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

// My imports
#include "sgx_tcrypto.h"
#include <stdint.h>

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
    for (int i = 0; i < size; i++)
        printf("%02x ", p[i]);
    printf("\n");
}

sgx_status_t do_challenge(sgx_aes_ctr_128bit_key_t *p_key, uint128_t p_ctr_e, uint128_t p_ctr_d) {
    sgx_status_t sgx_status;
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

    // Decrypt the challenge ctxt
    char ptxt_challenge[sizeof(int)*2] = {0};
    sgx_status = sgx_aes_ctr_decrypt(p_key, (uint8_t *)rem_ctxt_challenge, len, (uint8_t *)&p_ctr_d, 16, (uint8_t *)ptxt_challenge);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_decrypt\n");
        return sgx_status;
    }
    printf("Decrypted challange\n");
    //print_mem_content((unsigned char *)ptxt_challenge, len);

    // Now split it back up in the two ints
    int a, b;
    memcpy((char *)&a, ptxt_challenge, sizeof(int));
    memcpy((char *)&b, ptxt_challenge+sizeof(int), sizeof(int));

    // Do the calculation that Bob does not want to leak
    int c = a + b;
    printf("Result is %x\n", c);
    // Encrypt the result and send it back
    char c_ctxt[sizeof(int)] = {0};
    sgx_status = sgx_aes_ctr_encrypt(p_key, (uint8_t *)&c, sizeof(int), (uint8_t *)&p_ctr_e, 1, (uint8_t *)c_ctxt);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_encrypt\n");
        return sgx_status;
    }
    ocall_send((char *)&c_ctxt, sizeof(int));
    printf("Encrypted c and sent\n");
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
    sgx_ec256_public_t p_public_B;
    sgx_status = sgx_ecc256_create_key_pair(&p_private, &p_public_B, ecc_handle);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_ecc256_create_key_pair\n");
        return sgx_status;
    }

    // send the public key
    size_t size = sizeof(p_public_B);
    ocall_send((char *)&p_public_B, size);
    printf("Sent key \n");
    //print_mem_content((unsigned char *)&p_public_B, size);

    // recv (main idea from https://stackoverflow.com/questions/45532406/why-in-sgx-enclave-string-argument-has-to-be-used-with-in-attribute)
    char *buffer; // pointer to string in untrusted memory that we would get form OCALL
    size_t len;  // length of string
    ocall_recv(&buffer, &len);
    // copy back value
    sgx_ec256_public_t p_public_A;
    memcpy(&p_public_A, buffer, len);
    printf("Got key \n");
    //print_mem_content((unsigned char *)&p_public_A, len);

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
    uint128_t p_ctr_e = 0;
    sgx_status = sgx_aes_ctr_encrypt(&p_key, (uint8_t *)PSK_B, HANDSHAKE_LEN, (uint8_t *)&p_ctr_e, 1, (uint8_t *)ctxt);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_encrypt\n");
        return sgx_status;
    }
    printf("Encrypted PSK success\n");
    //print_mem_content((unsigned char *)ctxt, HANDSHAKE_LEN);

    // Now send this PSK
    size = HANDSHAKE_LEN;
    ocall_send(ctxt, size);
    printf("Send out PSK: %s\n", PSK_B);

    // Receive the PSK from the other party and checks it's size
    ocall_recv(&buffer, &len);
    if (len != HANDSHAKE_LEN)
        return SGX_ERROR_UNEXPECTED;
    // copy back value we got
    char rem_ctxt[len] = {0};
    memcpy(&rem_ctxt, buffer, len);
    printf("Got remote PSK\n");
    // Decode the remote PSK and check it is correct size
    char PSK_A[HANDSHAKE_LEN] = {0};
    uint128_t p_ctr_d = 0;
    sgx_status = sgx_aes_ctr_decrypt(&p_key, (uint8_t *)rem_ctxt, HANDSHAKE_LEN, (uint8_t *)&p_ctr_d, 16, (uint8_t *)PSK_A);
    if (sgx_status != SGX_SUCCESS) {
        printf("Errored out at sgx_aes_ctr_decrypt\n");
        return sgx_status;
    }
    printf("Got remote PSK decrypted: %s\n", PSK_A);
    // Check against what we expect from the other side
    if (strncmp("I AM ALICE", PSK_A, HANDSHAKE_LEN) != 0) {
        printf("The PSK is not the expected one!\n");
        // TODO split this part off into a seperate ECALL
        return SGX_ERROR_UNEXPECTED;
    }

    // Do the whole thing 20 times
    for (int i = 1; i < 21; i++) {
        sgx_status = do_challenge(&p_key, p_ctr_e, p_ctr_d);
        if (sgx_status != SGX_SUCCESS) {
            printf("Errored out at do_challenge\n");
            return sgx_status;
        }
        printf("Nice, we sent c! (%d)\n", i);
    }

    return SGX_SUCCESS;
}
