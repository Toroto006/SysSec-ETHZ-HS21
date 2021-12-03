// Base idea for this from https://softwareengineering.stackexchange.com/questions/262897/local-communications-between-two-apps

#include "Comm.h"

int obj_socket = 0;
int sock;

int init_server() {
    struct sockaddr_in address;
    int opted = 1;
    int address_length = sizeof(address);
    if (( obj_socket = socket( AF_INET, SOCK_STREAM, 0)) == 0) {
        perror( "Opening of Socket Failed !");
        exit( EXIT_FAILURE);
    }
    if ( setsockopt(obj_socket, SOL_SOCKET, SO_REUSEADDR, &opted, sizeof ( opted ))) {
        perror( "Can't set the socket" );
        exit( EXIT_FAILURE );
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );
    if (bind(obj_socket, ( struct sockaddr * )&address, sizeof(address))<0) {
        perror( "Binding of socket failed !" );
        exit(EXIT_FAILURE);
    }
    if (listen( obj_socket, 1) < 0) {
        perror( "Can't listen from the App B !");
        exit(EXIT_FAILURE);
    }
    if ((sock = accept(obj_socket, (struct sockaddr *)&address, (socklen_t*)&address_length)) < 0) {
        perror("Could not accept connection to an App A!");
        exit(EXIT_FAILURE);
    }
    return 0;
}

int send_msg(char *message) {
    //char *message = "A message from App B!";
    if (sock == 0) {
        printf( "Trying to send without creating socket first!" );
        return -1;
    }
    send( sock , message , MSG_LEN , 0 );
    //printf("\nSend: %s has been sent!\n", message);
    return 0;
}

ssize_t recv_msg(char *buffer) {
    if (sock == 0) {
        printf( "Trying to recv without creating socket first!" );
        return -1;
    }
    ssize_t reader;
    reader = read( sock, buffer, MSG_LEN );
    //printf("Recv: %s\n", buffer );
    return reader;
}

int close_server() {
    if (obj_socket == 0) {
        printf( "Trying to close without creating socket first!" );
        return -1;
    }
    close(obj_socket);
    return 0;
}