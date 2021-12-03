// Base idea for this from https://softwareengineering.stackexchange.com/questions/262897/local-communications-between-two-apps

#include "Comm.h"

int obj_socket = 0;

int init_client(){
    struct sockaddr_in serv_addr;
    if (( obj_socket = socket (AF_INET, SOCK_STREAM, 0 )) < 0) {
        printf( "Socket creation error !" );
        return -1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    // Converting IPv4 and IPv6 addresses from text to binary form
    if(inet_pton( AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf( "\nInvalid address ! This IP Address is not supported !\n" );
        return -1;
    }
    if ( connect( obj_socket, (struct sockaddr *) &serv_addr, sizeof(serv_addr )) < 0) {
        printf( "Connection Failed : Can't establish a connection over this socket!\n" );
        return -1;
    }
    return 0;
}

int send_msg(char *message) {
    if (obj_socket == 0) {
        printf( "Trying to send without creating socket first!\n" );
        return -1;
    }
    send( obj_socket , message , MSG_LEN , 0 );
    //printf("\nSend: %s has been sent!\n", message);
    return 0;
}

ssize_t recv_msg(char *buffer) {
    if (obj_socket == 0) {
        printf( "Trying to recv without creating socket first!\n" );
        return -1;
    }
    ssize_t reader;
    reader = read( obj_socket, buffer, MSG_LEN );
    //printf("Recv: %s\n", buffer );
    return reader;
}

int close_client(){
    if (obj_socket == 0) {
        printf( "Trying to close without creating socket first!\n" );
        return -1;
    }
    close(obj_socket);
    return 0;
}