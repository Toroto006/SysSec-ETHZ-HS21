#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>

/*************************
 * BEGIN [my imports and defines]
 *************************/
#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

// IPC between apps
#include "Comm.h"

// The buffer we use to give the enclave data
char copy_buffer[MSG_LEN] = {0};

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
/*************************
 * END [my imports and defines]
 *************************/

/*************************
 * BEGIN [error handling]
 *************************/
typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}
/*************************
 * END [error handling]
 *************************/

/*************************
 * BEGIN [enclave initialization function]
 *************************/
/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}
/*************************
 * END [enclave initialization function]
 *************************/

/*************************
 * BEGIN [debug function memory print]
 *************************/
void print_mem_content(unsigned char *p, size_t size){
  // from https://stackoverflow.com/questions/2376915/how-to-print-out-the-memory-contents-of-a-variable-in-c
  for (long unsigned int i = 0; i < size; i++)
    printf("%02x ", p[i]);
  printf("\n");
}
/*************************
 * END [debug function memory print]
 *************************/

/*************************
 * BEGIN [OCALL function definitions]
 *************************/
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

/*************************
 * BEGIN [OCALL app part to send IPC message]
 *************************/
// The OCALL send from the enclave
// Based on the SGX samples
void ocall_send(char *buffer, size_t len) {
    //printf("OCALL send len: %ld\n", len);
    // Prepare the message to be send
    char buf[MSG_LEN] = {0};
    // Prepend the len to actually use
    memcpy(buf, (char *)&len, sizeof(size_t));
    // Copy in the message
    memcpy(buf+sizeof(size_t), buffer, len);
    // Actually send
    //print_mem_content((unsigned char *)buffer, 64);
    send_msg(buf);
}
/*************************
 * END [OCALL app part to send IPC message]
 *************************/

/*************************
 * BEGIN [OCALL app part to recv IPC message]
 *************************/
// recv (Based on https://stackoverflow.com/questions/45532406/why-in-sgx-enclave-string-argument-has-to-be-used-with-in-attribute)
void ocall_recv(char **buffer_ptr, size_t *len) {
    // First receive the msg over the network
    char msg_buffer[MSG_LEN] = {0};
    recv_msg(msg_buffer);
    // Read the return size_t from the start
    memcpy(len, msg_buffer, sizeof(size_t));
    //printf("OCALL recv: %ld\n", *len);
    //print_mem_content((unsigned char *)msg_buffer+8, 64);
    // Copy len of msg over to enclave buf
    *buffer_ptr = copy_buffer;
    memcpy(copy_buffer, msg_buffer+sizeof(size_t), *len);
}
/*************************
 * END [OCALL app part to recv IPC message]
 *************************/
/*************************
 * END [OCALL function definitions]
 *************************/

/*************************
 * BEGIN [main APP A function]
 *************************/
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    // Initialize communication to App B
    if(init_client() < 0){
        printf("Connection to App B failed. Make sure it is running!\n");
        return -1;
    }
    /*************************
     * BEGIN [initialize the enclave using the function defined before]
     *************************/
    if(initialize_enclave() < 0){
        printf("Enclave initialization failed.\n");
        return -1;
    }
    printf("From App: Enclave creation success.\n");
    /*************************
     * END [initialize the enclave using the function defined before]
     *************************/
    
    /*************************
     * BEGIN [createEnclave]
     *************************/
    // The following is again from the SealUnseal Sample of SGX
    // Get the sealed data size
    sgx_status_t sgx_status;
    uint32_t sealed_data_size = 0;
    sgx_status = get_sealed_size(global_eid, &sealed_data_size);
    if (sgx_status != SGX_SUCCESS)
    {
        print_error_message(sgx_status);
        sgx_destroy_enclave(global_eid);
        return -1;
    } else if(sealed_data_size == UINT32_MAX) {
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    
    uint8_t *sealed_key = (uint8_t *)malloc(sealed_data_size);
    if(sealed_key == NULL)
    {
        printf("Out of memory");
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    // Now that we were able to create the buffers use them to create the enclave
    // and get the shared key as a sealed key
    sgx_status_t retval;
    sgx_status = createEnclave(global_eid, &retval, sealed_key, sealed_data_size);
    if (sgx_status != SGX_SUCCESS)
    {
        print_error_message(sgx_status);
        free(sealed_key);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    else if( retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        free(sealed_key);
        sgx_destroy_enclave(global_eid);
        return -1;
    }
    printf("From App: createEnclave success.\n");
    /*************************
     * END [createEnclave]
     *************************/

    /*************************
     * BEGIN [getPSK ECALL with the check]
     *************************/
    // Now run the enclave getPSK
    getPSK(global_eid, &sgx_status, sealed_key, sealed_data_size);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        sgx_destroy_enclave(global_eid);
        printf("getPSK failed!");
        return -1;
    }
    /*************************
     * END [getPSK ECALL with the check]
     *************************/
    
    /*************************
     * BEGIN [doing the challenge 20 times]
     *************************/
    // Do 20 times the challange
    int success = 0;
    for (int i = 1; i < 21; i++) {
        getChallenge(global_eid, &sgx_status, sealed_key, sealed_data_size, i, &success);
        if (sgx_status != SGX_SUCCESS) {
            print_error_message(sgx_status);
            sgx_destroy_enclave(global_eid);
            printf("getPSK failed!");
            return -1;
        }
        if (!success) {
            printf("Bob was not able to calculate the result c correctly!!\n");
            break;
        }
        printf("Round %d success!\n", i);
    }
    /*************************
     * END [doing the challenge 20 times]
     *************************/
    /*************************
     * BEGIN [destroy enclave and connection]
     *************************/
    sgx_destroy_enclave(global_eid);
    printf("From App: Enclave destroyed.\n");
    close_client();
    printf("From App: Client socket close.\n");
    return 0;
    /*************************
     * END [destroy enclave and connection]
     *************************/
}
/*************************
 * END [main APP A function]
 *************************/