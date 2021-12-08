#! /bin/bash
(cd ./Enclave_B/ && make clean && make SGX_MODE=SIM) & (cd ./Enclave_A/ && make clean &> /dev/null && make SGX_MODE=SIM)