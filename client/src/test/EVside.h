#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "EXITypes.h"
#include "appHandEXIDatatypes.h"
#include "appHandEXIDatatypesEncoder.h"
#include "appHandEXIDatatypesDecoder.h"


/* Activate support for ISO1 */
#include "iso1EXIDatatypes.h"
#if DEPLOY_ISO1_CODEC == SUPPORT_YES
#include "iso1EXIDatatypesEncoder.h"
#include "iso1EXIDatatypesDecoder.h"
#endif /* DEPLOY_ISO1_CODEC == SUPPORT_YES */

/* Activate support for ISO2 */
#include "iso2EXIDatatypes.h"
#if DEPLOY_ISO2_CODEC == SUPPORT_YES
#include "iso2EXIDatatypesEncoder.h"
#include "iso2EXIDatatypesDecoder.h"
#endif /* DEPLOY_ISO2_CODEC == SUPPORT_YES */

#include "v2gtp.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfio.h>

extern uint8_t buffer1[];
extern uint8_t buffer2[];
extern unsigned char buff[256];
extern int ret;
extern int sockfd;
extern WOLFSSL_CTX* ctx;
extern WOLFSSL* ssl;

int clientssl_connect(int IP_VERSION, char** IP_ADDR, const char* CERT_FILE, const int DEFAULT_PORT);
int send2server(bitstream_t* iStream, bitstream_t* oStream);
static int writeStringToEXIString(char* string, exi_string_character_t* exiString);
static void printASCIIString(exi_string_character_t* string, uint16_t len);
static void printBinaryArray(uint8_t* byte, uint16_t len);
static void copyBytes(uint8_t* from, uint16_t len, uint8_t* to);
int appHandshake(char* protocol);
int charging1();
static void printEVSEStatus2(struct iso2EVSEStatusType* status);
static int serialize2EXI2Stream(struct iso2EXIDocument* exiIn, bitstream_t* stream);
static int deserialize2Stream2EXI(bitstream_t* streamIn, struct iso2EXIDocument* exi);
static int request_response2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
int charging2();
static void printEVSEStatus1(struct iso1DC_EVSEStatusType* status);
static int serialize1EXI2Stream(struct iso1EXIDocument* exiIn, bitstream_t* stream) ;
static int deserialize1Stream2EXI(bitstream_t* streamIn, struct iso1EXIDocument* exi) ;
static int request_response1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut);
int shutdown_connection();
int main_example(int IP_VERSION, char* IP_ADDR[]);


#endif /* CLIENT_FUNCTIONS_H */
