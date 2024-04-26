#ifndef EVSE_H
#define EVSE_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "EXITypes.h"

#include "appHandEXIDatatypes.h"
#include "appHandEXIDatatypesEncoder.h"
#include "appHandEXIDatatypesDecoder.h"

/* Activate support for DIN */
#include "dinEXIDatatypes.h"
#if DEPLOY_DIN_CODEC == SUPPORT_YES
#include "dinEXIDatatypesEncoder.h"
#include "dinEXIDatatypesDecoder.h"
#endif /* DEPLOY_DIN_CODEC == SUPPORT_YES */

/* Activate support for XMLDSIG */
#include "xmldsigEXIDatatypes.h"
#if DEPLOY_XMLDSIG_CODEC == SUPPORT_YES
#include "xmldsigEXIDatatypesEncoder.h"
#include "xmldsigEXIDatatypesDecoder.h"
#endif /* DEPLOY_XMLDSIG_CODEC == SUPPORT_YES */

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

#define BUFFER_SIZE 256

#define ERROR_UNEXPECTED_REQUEST_MESSAGE -601
#define ERROR_UNEXPECTED_SESSION_SETUP_RESP_MESSAGE -602
#define ERROR_UNEXPECTED_SERVICE_DISCOVERY_RESP_MESSAGE -602
#define ERROR_UNEXPECTED_SERVICE_DETAILS_RESP_MESSAGE -603
#define ERROR_UNEXPECTED_PAYMENT_SERVICE_SELECTION_RESP_MESSAGE -604
#define ERROR_UNEXPECTED_PAYMENT_DETAILS_RESP_MESSAGE -605
#define ERROR_UNEXPECTED_AUTHORIZATION_RESP_MESSAGE -606
#define ERROR_UNEXPECTED_CHARGE_PARAMETER_DISCOVERY_RESP_MESSAGE -607
#define ERROR_UNEXPECTED_POWER_DELIVERY_RESP_MESSAGE -608
#define ERROR_UNEXPECTED_CHARGING_STATUS_RESP_MESSAGE -609
#define ERROR_UNEXPECTED_METERING_RECEIPT_RESP_MESSAGE -610
#define ERROR_UNEXPECTED_SESSION_STOP_RESP_MESSAGE -611
#define ERROR_UNEXPECTED_CABLE_CHECK_RESP_MESSAGE -612
#define ERROR_UNEXPECTED_PRE_CHARGE_RESP_MESSAGE -612
#define ERROR_UNEXPECTED_CURRENT_DEMAND_RESP_MESSAGE -613
#define ERROR_UNEXPECTED_WELDING_DETECTION_RESP_MESSAGE -614

// Global variables (if necessary)
extern uint8_t buffer1[BUFFER_SIZE];
extern uint8_t buffer2[BUFFER_SIZE];
extern unsigned char buff[BUFFER_SIZE];
extern int countcase;
extern int finished;
#if DEPLOY_ISO1_CODEC == SUPPORT_YES
extern struct iso1EXIDocument exiIn1;
extern struct iso1EXIDocument exiOut1;
extern struct iso1ServiceDetailResType serviceDetailRes1;
extern struct iso1PaymentDetailsResType paymentDetailsRes1;
#endif /* DEPLOY_ISO1_CODEC == SUPPORT_YES */


#if DEPLOY_ISO2_CODEC == SUPPORT_YES
extern struct iso2EXIDocument exiIn2;
extern struct iso2EXIDocument exiOut2;

extern struct iso2ServiceDetailResType serviceDetailRes2;
extern struct iso2PaymentServiceSelectionResType paymentServiceSelectionRes;
extern struct iso2PaymentDetailsResType paymentDetailsRes2;
#endif /* DEPLOY_ISO2_CODEC == SUPPORT_YES */

// Function prototypes
static int writeStringToEXIString(char* string, exi_string_character_t* exiString);
static void printASCIIString(exi_string_character_t* string, uint16_t len);
static void printBinaryArray(uint8_t* byte, uint16_t len);
static void copyBytes(uint8_t* from, uint16_t len, uint8_t* to);
static int appHandshakeHandler(bitstream_t* iStream, bitstream_t* oStream);
static int appHandshake(bitstream_t* stream1, bitstream_t* stream2);

#if DEPLOY_ISO2_CODEC == SUPPORT_YES
static void printEVSEStatus2(struct iso2EVSEStatusType* status);
static int deserialize2Stream2EXI(bitstream_t* streamIn, struct iso2EXIDocument* exi);
static int sessionSetup2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int serviceDiscovery2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int serviceDetail2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int paymentServiceSelection2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int paymentDetails2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int authorization2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int chargeParameterDiscovery2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int powerDelivery2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int chargingStatus2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int meteringReceipt2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int sessionStop2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int cableCheck2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int preCharge2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int create_response_message2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int request_response2(bitstream_t* stream1, bitstream_t* stream2 ,struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut);
static int charging2(bitstream_t* stream1, bitstream_t* stream2);
#endif /* DEPLOY_ISO1_CODEC == SUPPORT_YES */

#if DEPLOY_ISO1_CODEC == SUPPORT_YES
static int serialize1EXI2Stream(struct iso1EXIDocument* exiIn, bitstream_t* stream);
static int deserialize1Stream2EXI(bitstream_t* streamIn, struct iso1EXIDocument* exi);
static int sessionSetup1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut);
static int serviceDetail1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut);
static int authorization1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut);
static int powerDelivery1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut);
static int chargingStatus1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut);
static int meteringReceipt1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut);
static int sessionStop1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut);
static int cableCheck1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut);
static int preCharge1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut);
static int create_response_message1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut);
static int request_response1(bitstream_t* stream1, bitstream_t* stream2 , struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut);
static int charging1(bitstream_t* stream1, bitstream_t* stream2) ;
#endif /* DEPLOY_ISO1_CODEC == SUPPORT_YES */

void server_tls(const char *CERT_FILE, const char *KEY_FILE, int DEFAULT_PORT);
int write_response(WOLFSSL *ssl, bitstream_t *stream2);
int initialize_wolfssl(const char *CERT_FILE, const char *KEY_FILE, int *sockfd, WOLFSSL_CTX **ctx);
void configure_server_address(struct sockaddr_in *servAddr, int DEFAULT_PORT);
int bind_server_socket(int sockfd, struct sockaddr_in *servAddr);
void accept_and_handle_client_connections(int sockfd, WOLFSSL_CTX *ctx);
int handle_client_connection(WOLFSSL *ssl, int connd);
void cleanup_and_exit(WOLFSSL *ssl, int connd, int sockfd, WOLFSSL_CTX *ctx);


#endif // EVSE_H