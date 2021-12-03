#! /bin/bash
(cd ./Enclave_B/ && ./app_B) & A=$(cd ./Enclave_A/ && sleep 0.2 && ./app_A)
red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`
echo "${green} ${A} ${reset}"