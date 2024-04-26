/*
 * Copyright (C) 2007-2018 Siemens AG
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*******************************************************************
 *
 * @author Daniel.Peintner.EXT@siemens.com
 * @author Sebastian.Kaebisch@siemens.com
 * @version 0.9.4
 * @contact Richard.Kuntschke@siemens.com
 *
 *
 ********************************************************************/


#include <EVside.h>

#define BUFFER_SIZE 256
uint8_t buffer1[BUFFER_SIZE];
uint8_t buffer2[BUFFER_SIZE];

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



unsigned char      buff[256];
int                ret;
int                sockfd;
/* declare wolfSSL objects */
WOLFSSL_CTX* ctx;
WOLFSSL*     ssl;

/**
 * Establishes an SSL/TLS connection with a server using the wolfSSL library.
 *
 * @param IP_VERSION    The IP version to use (currently supports IPv4 only).
 * @param IP_ADDR       An array of strings representing IP addresses (IPv4 format).
 * @param CERT_FILE     Path to the CA certificate file for server verification.
 * @param DEFAULT_PORT  The default port number for the SSL/TLS connection.
 * @return              0 on success, -1 on failure.
 *
 * @note This function assumes IPv4 addresses and uses TCP (stream-based) sockets.
 * 		 You need to declare and initialize WOLFSSL_CTX* ctx and WOLFSSL* ssl before calling this function.
 *       Make sure to include necessary error handling and validation for the parameters and return values.
 */
int clientssl_connect(int IP_VERSION,char **IP_ADDR,const char *CERT_FILE, const int DEFAULT_PORT)
{	
	struct sockaddr_in servAddr;
        /* Check for proper calling convention */
    if (IP_VERSION != 2) {
        printf("usage: %s <IPv4 address>\n", IP_ADDR[0]);
        return 0;
    }

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1;
        goto end;
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;             /* using IPv4      */
    servAddr.sin_port   = htons(DEFAULT_PORT); /* on DEFAULT_PORT */

    /* Get the server IPv4 address from the command line call */
    if (inet_pton(AF_INET, IP_ADDR[1], &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        ret = -1;
        goto end;
    }

    /* Connect to the server */
    if ((ret = connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)))
         == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        goto end;
    }
    /*---------------------------------*/
    /* Start of wolfSSL initialization and configuration */
    /*---------------------------------*/
    /* Initialize wolfSSL */
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto socket_cleanup;
    }

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1;
        goto socket_cleanup;
    }

    /* Load client certificates into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL))
         != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CERT_FILE);
        goto ctx_cleanup;
    }

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1;
        goto ctx_cleanup;
    }

    /* Attach wolfSSL to the socket */
    if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto cleanup;
    }

    /* Connect to wolfSSL on the server side */
    if ((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        goto cleanup;
    }

    return ret;

    /* Bidirectional shutdown */
    while (wolfSSL_shutdown(ssl) == WOLFSSL_SHUTDOWN_NOT_DONE) {
        printf("Shutdown not complete\n");
    }

    printf("Shutdown complete\n");

    ret = 0;

    /* Cleanup and return */
cleanup:
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
ctx_cleanup:
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
socket_cleanup:
    close(sockfd);          /* Close the connection to the server       */
end:
    return ret;               /* Return reporting a success               */
}

/**
 * Sends a message to a server using an SSL/TLS connection and reads the server's response.
 *
 * @param iStream   Pointer to the input bitstream containing the message to send.
 * @param oStream   Pointer to the output bitstream to store the server's response.
 * @return          0 on success, or an error code indicating failure.
 */
int send2server(bitstream_t* iStream, bitstream_t* oStream)
{	

    printf("Send Message To Server: ");
	memset(buff, 0, sizeof(buff));
	memcpy(buff, iStream->data, iStream->size);
	int len = 256;
	// for(int i=0;i<256;i++){
	// 	printf("Byte #%d = %d, Steam1 = %d\n",i,buff[i],iStream->data[i]);
	// }
    /* Send the message to the server */
    if ((ret = wolfSSL_write(ssl, buff, 256)) != len) {
        fprintf(stderr, "ERROR: failed to write entire message\n");
        fprintf(stderr, "%d bytes of %d bytes were sent", ret, (int) len);
        goto cleanup;
    }
read:
    /* Read the server data into our buff array */
    memset(buff, 0, sizeof(buff));
    if ((ret = wolfSSL_read(ssl, buff, sizeof(buff)-1)) == -1) {
        fprintf(stderr, "ERROR: failed to read\n");
        goto cleanup;
    }
	if (buff[0]==0){
		goto read;
	}
	oStream->data = buff;
	// 	for(int i=0;i<256;i++){
	// 	printf("Byte #%d = %d, Steam1 = %d\n",i,buff[i],oStream->data[i]);
	// }
    return 0;
        /* Cleanup and return */
cleanup:
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
    close(sockfd);          /* Close the connection to the server       */
    return ret;               /* Return reporting a success               */
}


/**
 * Writes a C-style string to an EXI string.
 *
 * @param string The input C-style string to be written.
 * @param exiString The EXI string where the C-style string will be written.
 * @return The length of the written EXI string.
 */
static int writeStringToEXIString(char* string, exi_string_character_t* exiString) {
	int pos = 0;
	while(string[pos]!='\0')
	{
		exiString[pos] = string[pos];
		pos++;
	}

	return pos;
}

/**
 * Prints an ASCII string represented as an EXI string.
 *
 * @param string The EXI string representing the ASCII characters.
 * @param len The length of the EXI string.
 */
static void printASCIIString(exi_string_character_t* string, uint16_t len) {
	unsigned int i;
	for(i=0; i<len; i++) {
		printf("%c",(char)string[i]);
	}
	printf("\n");
}

/**
 * Prints a binary array as a sequence of integers.
 *
 * @param byte The binary array to be printed.
 * @param len The length of the binary array.
 */
static void printBinaryArray(uint8_t* byte, uint16_t len) {
	unsigned int i;
	for(i=0; i<len; i++) {
		printf("%d ",byte[i]);
	}
	printf("\n");
}

/**
 * Copies bytes from one array to another.
 *
 * @param from The source array from which bytes are copied.
 * @param len The length of bytes to copy.
 * @param to The destination array where bytes will be copied.
 */
static void copyBytes(uint8_t* from, uint16_t len, uint8_t* to) {
	int i;
	for(i=0; i<len; i++) {
		to[i] = from[i];
	}
}

/**
 * Negotiates the protocol between the Electric Vehicle Communication Controller (EVCC) and the Supply Equipment Communication Controller (SECC).
 *
 * This function initiates the application handshake protocol to negotiate the supported application protocol between the EVCC and SECC.
 *
 *
 * @param protocol  The protocol to use for the application handshake.
 *                  For example, "urn:iso:15118:2:2010:MsgDef".
 * @return          0 on success, -1 on failure.
 */
int appHandshake(char* protocol)
{	
	printf("+++ Start application handshake protocol example +++\n\n");
	bitstream_t stream1;
	bitstream_t stream2;

	uint32_t payloadLengthDec;
	size_t pos1 = V2GTP_HEADER_LENGTH; /* v2gtp header */
	size_t pos2 = 0;

	struct appHandEXIDocument handshake;
	struct appHandEXIDocument handshakeResp;

	int errn = 0;

	// char* ns0 = "urn:iso:15118:2:2010:MsgDef";
	// char* ns1 = "urn:din:70121:2012:MsgDef";

	stream1.size = BUFFER_SIZE;
	stream1.data = buffer1;
	stream1.pos = &pos1;

	stream2.size = BUFFER_SIZE;
	stream2.data = buffer2;
	stream2.pos = &pos2;

	init_appHandEXIDocument(&handshake);

	printf("EV side: setup data for the supported application handshake request message\n");

	/* set up ISO/IEC 15118 Version 1.0 information */
	handshake.supportedAppProtocolReq_isUsed = 1u;
	handshake.supportedAppProtocolReq.AppProtocol.arrayLen = 1; /* we have only two protocols implemented */

	handshake.supportedAppProtocolReq.AppProtocol.array[0].ProtocolNamespace.charactersLen =
			writeStringToEXIString(protocol, handshake.supportedAppProtocolReq.AppProtocol.array[0].ProtocolNamespace.characters);
	handshake.supportedAppProtocolReq.AppProtocol.array[0].SchemaID = 1;
	handshake.supportedAppProtocolReq.AppProtocol.array[0].VersionNumberMajor = 1;
	handshake.supportedAppProtocolReq.AppProtocol.array[0].VersionNumberMinor = 0;
	handshake.supportedAppProtocolReq.AppProtocol.array[0].Priority = 1;


	/* send app handshake request */
	if( (errn = encode_appHandExiDocument(&stream1, &handshake)) == 0) {
		if ( write_v2gtpHeader(stream1.data, pos1-V2GTP_HEADER_LENGTH, V2GTP_EXI_TYPE) == 0 ) {
			printf("EV side: send message to the EVSE\n");
		}
	}


	if (errn == 0){
		errn = send2server(&stream1, &stream2);
	}
	if (errn == 0) {
		/* check response */
		if ( (errn = read_v2gtpHeader(stream2.data, &payloadLengthDec)) == 0) {
			pos2 = V2GTP_HEADER_LENGTH;
			if(decode_appHandExiDocument(&stream2, &handshakeResp) == 0) {
				printf("EV side: Response of the EVSE \n");
				if(handshakeResp.supportedAppProtocolRes.ResponseCode == appHandresponseCodeType_OK_SuccessfulNegotiation) {
					printf("\t\tResponseCode=OK_SuccessfulNegotiation\n");
					printf("\t\tSchemaID=%d\n",handshakeResp.supportedAppProtocolRes.SchemaID);
				}
			}
		}
		else {
			printf("+++ Terminate application handshake protocol example with errn = %d +++\n\n", errn);
			printf("appHandshake error %d \n", errn);
		}

	}

	if (errn != 0) {
		printf("+++ Terminate application handshake protocol example with errn = %d +++\n\n", errn);
		printf("appHandshake error %d \n", errn);
	}


	return errn;

}





#if DEPLOY_ISO2_CODEC == SUPPORT_YES

static void printEVSEStatus2(struct iso2EVSEStatusType* status)
{
	printf("\tEVSEStatus:\n");
	printf("\t\tEVSENotification=%d\n", status->EVSENotification);
	printf("\t\tNotificationMaxDelay=%d\n", status->NotificationMaxDelay);
}

/**
 * Serializes an ISO2 EXI document into a bitstream for transmission.
 * This function encodes the input ISO1 EXI document into the provided bitstream
 * and adds the V2GTP header for EXI data type.
 *
 * @param exiIn Pointer to the ISO1 EXI document to be serialized.
 * @param stream Pointer to the bitstream where the serialized data will be stored.
 * @return 0 on success, or an error code indicating failure.
 */
static int serialize2EXI2Stream(struct iso2EXIDocument* exiIn, bitstream_t* stream) {
	int errn;
	*stream->pos = V2GTP_HEADER_LENGTH;  /* v2gtp header */
	if( (errn = encode_iso2ExiDocument(stream, exiIn)) == 0) {
		errn = write_v2gtpHeader(stream->data, (*stream->pos)-V2GTP_HEADER_LENGTH, V2GTP_EXI_TYPE);
	}
	return errn;
}


/**
 * Deserializes an EXI-encoded bitstream into an ISO1 EXI document.
 * This function reads an EXI-encoded bitstream, extracts the ISO1 EXI document,
 * and decodes it into the provided ISO1 EXI document structure.
 *
 * @param streamIn Pointer to the input bitstream containing the EXI-encoded data.
 * @param exi Pointer to the ISO1 EXI document structure where the decoded data will be stored.
 * @return 0 on success, or an error code indicating failure.
 */
static int deserialize2Stream2EXI(bitstream_t* streamIn, struct iso2EXIDocument* exi) {
	int errn;
	uint32_t payloadLength;

	*streamIn->pos = 0;
	if ( (errn = read_v2gtpHeader(streamIn->data, &payloadLength)) == 0) {
		*streamIn->pos += V2GTP_HEADER_LENGTH;

		errn = decode_iso2ExiDocument(streamIn, exi);
	}
	return errn;
}

/**
 * Sends a request to the server and receives a response using the ISO1 protocol.
 * This function serializes the input EXI document, sends it to the server, receives the response,
 * and deserializes it into the output EXI document.
 *
 * @param exiIn Pointer to the input EXI document to be sent.
 * @param exiOut Pointer to the output EXI document to store the response.
 * @return 0 on success, or an error code indicating failure.
 */
static int request_response2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {
	int errn;
	bitstream_t stream1;
	bitstream_t stream2;

	size_t pos1;
	size_t pos2;

	stream1.size = BUFFER_SIZE;
	stream1.data = buffer1;
	stream1.pos = &pos1;

	stream2.size = BUFFER_SIZE;
	stream2.data = buffer2;
	stream2.pos = &pos2;

	/* EV side */
	errn = serialize2EXI2Stream(exiIn, &stream1);

	if(errn == 0){
		errn = send2server(&stream1, &stream2);
	}


	/* EV side */
	/* deserialize response message */
	if (errn == 0) {
		errn = deserialize2Stream2EXI(&stream2, exiOut);
	}

	return errn;
}

/**
 * Initiates the V2G client/service example for charging (ISO2).
 * This function handles the V2G communication protocol for charging, including session setup,
 * service details, authorization, cable check, pre-charge, power delivery, charging status, and session stop.
 *
 * @return 0 on success, or an error code indicating failure.
 */
int charging2()
{
	int errn = 0;
	int i, j;

	struct iso2EXIDocument exiIn;
	struct iso2EXIDocument exiOut;

	struct iso2ServiceDetailResType serviceDetailRes;
	struct iso2PaymentServiceSelectionResType paymentServiceSelectionRes;
	struct iso2PaymentDetailsResType paymentDetailsRes;

	/* setup header information */
	init_iso2EXIDocument(&exiIn);
	exiIn.V2G_Message_isUsed = 1u;
	init_iso2MessageHeaderType(&exiIn.V2G_Message.Header);
	exiIn.V2G_Message.Header.SessionID.bytes[0] = 0; /* sessionID is always '0' at the beginning (the response contains the valid sessionID)*/
	exiIn.V2G_Message.Header.SessionID.bytes[1] = 0;
	exiIn.V2G_Message.Header.SessionID.bytes[2] = 0;
	exiIn.V2G_Message.Header.SessionID.bytes[3] = 0;
	exiIn.V2G_Message.Header.SessionID.bytes[4] = 0;
	exiIn.V2G_Message.Header.SessionID.bytes[5] = 0;
	exiIn.V2G_Message.Header.SessionID.bytes[6] = 0;
	exiIn.V2G_Message.Header.SessionID.bytes[7] = 0;
	exiIn.V2G_Message.Header.SessionID.bytesLen = 8;
	exiIn.V2G_Message.Header.Signature_isUsed = 0u;


	/************************
	 * sessionSetup *
	 ************************/
	init_iso2BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.SessionSetupReq_isUsed = 1u;

	init_iso2SessionSetupReqType(&exiIn.V2G_Message.Body.SessionSetupReq);

	exiIn.V2G_Message.Body.SessionSetupReq.EVCCID.bytesLen = 1;
	exiIn.V2G_Message.Body.SessionSetupReq.EVCCID.bytes[0] = 10;

	printf("EV side: call EVSE sessionSetup");

	errn = request_response2(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.SessionSetupRes_isUsed) {
			/* show results of EVSEs answer message */
			init_iso1MessageHeaderType(&exiIn.V2G_Message.Header);
			exiIn.V2G_Message.Header.SessionID.bytes[0] = exiOut.V2G_Message.Header.SessionID.bytes[0];
			exiIn.V2G_Message.Header.SessionID.bytes[1] = exiOut.V2G_Message.Header.SessionID.bytes[1];
			exiIn.V2G_Message.Header.SessionID.bytes[2] = exiOut.V2G_Message.Header.SessionID.bytes[2];
			exiIn.V2G_Message.Header.SessionID.bytes[3] = exiOut.V2G_Message.Header.SessionID.bytes[3];
			exiIn.V2G_Message.Header.SessionID.bytes[4] = exiOut.V2G_Message.Header.SessionID.bytes[4];
			exiIn.V2G_Message.Header.SessionID.bytes[5] = exiOut.V2G_Message.Header.SessionID.bytes[5];
			exiIn.V2G_Message.Header.SessionID.bytes[6] = exiOut.V2G_Message.Header.SessionID.bytes[6];
			exiIn.V2G_Message.Header.SessionID.bytes[7] = exiOut.V2G_Message.Header.SessionID.bytes[7];
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\tResponseCode=%d\n", exiOut.V2G_Message.Body.SessionSetupRes.ResponseCode);
			printf("\tEVSEID=%d\n",	exiOut.V2G_Message.Body.SessionSetupRes.EVSEID.characters[1]);
			printf("\tEVSETimeStamp=%li\n", (long int)exiOut.V2G_Message.Body.SessionSetupRes.EVSETimeStamp);
		} else {
			errn = ERROR_UNEXPECTED_SESSION_SETUP_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}


	/*******************************************
	 * serviceDiscovery *
	 *******************************************/
	init_iso2BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.ServiceDiscoveryReq_isUsed = 1u;

	init_iso2ServiceDiscoveryReqType(&exiIn.V2G_Message.Body.ServiceDiscoveryReq);

	exiIn.V2G_Message.Body.ServiceDiscoveryReq.SupportedServiceIDs_isUsed = 1u;
	exiIn.V2G_Message.Body.ServiceDiscoveryReq.SupportedServiceIDs.ServiceID.arrayLen = 1;
	exiIn.V2G_Message.Body.ServiceDiscoveryReq.SupportedServiceIDs.ServiceID.array[0] = iso2serviceCategoryType_Internet;

	printf("EV side: call EVSE serviceDiscovery");

	errn = request_response2(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.ServiceDiscoveryRes_isUsed) {
			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n",  exiOut.V2G_Message.Body.ServiceDiscoveryRes.ResponseCode);

			printf("\t Service ResponseCode=%d\n",	exiOut.V2G_Message.Body.ServiceDiscoveryRes.ResponseCode);

			/*printf("\t ServiceID=%d\n",	exiOut.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceID);
			printf("\t ServiceName=");
			printASCIIString(serviceDiscoveryRes.ChargeService.ServiceName.characters, serviceDiscoveryRes.ChargeService.ServiceName.charactersLen);
			if(serviceDiscoveryRes.PaymentOptionList.PaymentOption.array[1] == v2gpaymentOptionType_Contract) {
				printf("\t PaymentOption=Contract_paymentOptionType\n");
			}
			if(serviceDiscoveryRes.ChargeService.FreeService==1) {
				printf("\t ChargeService.FreeService=True\n");
			}
			if(serviceDiscoveryRes.ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.array[0] == v2gEnergyTransferModeType_DC_combo_core) {
				printf("\t EnergyTransferMode=AC_single_DC_core\n");
			}
			if(serviceDiscoveryRes.ChargeService.SupportedEnergyTransferMode.EnergyTransferMode.array[1] == v2gEnergyTransferModeType_AC_single_phase_core) {
				printf("\t EnergyTransferMode=AC_single_phase_core_EnergyTransferModeType\n");
			}
			printf("\t Value added service list:\n");
			for(i=0;i<serviceDiscoveryRes.ServiceList.Service.arrayLen;i++)
			{
				printf("\n\t\t ServiceID=%d\n",	serviceDiscoveryRes.ServiceList.Service.array[i].ServiceID);
				printf("\t\t ServiceName=");
				printASCIIString(serviceDiscoveryRes.ServiceList.Service.array[i].ServiceName.characters, exiOut.V2G_Message.Body.ServiceDiscoveryRes.ServiceList.Service.array[i].ServiceName.charactersLen );
				if(serviceDiscoveryRes.ServiceList.Service.array[i].ServiceCategory == v2gserviceCategoryType_Internet) {
					printf("\t\t ServiceCategory=Internet\n");
				}
				if(serviceDiscoveryRes.ServiceList.Service.array[i].FreeService==1) {
					printf("\t\t FreeService=True\n");
				}
			}*/

		} else {
			errn = ERROR_UNEXPECTED_SERVICE_DISCOVERY_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}


	/*********************************
	 * ServiceDetails *
	 *********************************/
	init_iso2BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.ServiceDetailReq_isUsed = 1u;

	init_iso2ServiceDetailReqType(&exiIn.V2G_Message.Body.ServiceDetailReq);

	exiIn.V2G_Message.Body.ServiceDetailReq.ServiceID = 22; /* Value Added Server ID */

	printf("EV side: call EVSE ServiceDetail \n");

	errn = request_response2(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.ServiceDetailRes_isUsed) {
			serviceDetailRes = exiOut.V2G_Message.Body.ServiceDetailRes;
			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n",  exiOut.V2G_Message.Body.ServiceDiscoveryRes.ResponseCode);
			printf("\t ServiceID=%d\n",	exiOut.V2G_Message.Body.ServiceDetailRes.ServiceID);

			if(serviceDetailRes.ServiceParameterList_isUsed) {
				printf("\t\tLength=%d\n", serviceDetailRes.ServiceParameterList.ParameterSet.arrayLen );/*TEST*/

				for(i=0; i<serviceDetailRes.ServiceParameterList.ParameterSet.arrayLen; i++)
				{
					printf("\t\tServiceSetID=%d\n", serviceDetailRes.ServiceParameterList.ParameterSet.array[i].ParameterSetID);
					printf("\t\tParameters=%d\n", serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.arrayLen);

					for(j=0; j<serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.arrayLen; j++)
					{
						printf("\t\t\t %d: ParameterName=", j+1);
						printASCIIString(serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].Name.characters, exiOut.V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].Name.charactersLen);

						/*if(serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].shortValue_isUsed == 1u) {
							printf("\t\t\t %d: StringValue=", j+1);
							printASCIIString(serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].stringValue.characters, serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].stringValue.charactersLen);
						} else if(serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].intValue_isUsed == 1u) {
							printf("\t\t\t %d: IntValue=%d\n", j+1, serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].intValue);
						} else if(serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].physicalValue_isUsed == 1u) {
							printf("\t\t\t %d: PhysicalValue=%d (%d)\n",  j+1, serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].physicalValue.Value, serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].physicalValue.Multiplier);
						}*/
					}
				}
			}
		} else {
			errn = ERROR_UNEXPECTED_SERVICE_DETAILS_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}


	/*******************************************
	 * ServicePaymentSelection *
	 *******************************************/
	init_iso2BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.PaymentServiceSelectionReq_isUsed = 1u;

	init_iso2PaymentServiceSelectionReqType(&exiIn.V2G_Message.Body.PaymentServiceSelectionReq);

	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedPaymentOption = iso2paymentOptionType_ExternalPayment;
	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedVASList_isUsed = 0u;
	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedEnergyTransferService.ServiceID = 1;
	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedEnergyTransferService.ParameterSetID = 4;

	printf("EV side: call EVSE ServicePaymentSelection \n");

	errn = request_response2(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.PaymentServiceSelectionRes_isUsed) {
			paymentServiceSelectionRes = exiOut.V2G_Message.Body.PaymentServiceSelectionRes;

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			if(exiOut.V2G_Message.Body.PaymentServiceSelectionRes.EVSEStatus_isUsed) {
				printf("\tHeader SessionID=");
				printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			}
			printf("\t ResponseCode=%d\n",  paymentServiceSelectionRes.ResponseCode);

		} else {
			errn = ERROR_UNEXPECTED_PAYMENT_SERVICE_SELECTION_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}


	/**********************************
	 * PaymentDetails *
	 **********************************/
	init_iso2BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.PaymentDetailsReq_isUsed = 1u;

	init_iso2PaymentDetailsReqType(&exiIn.V2G_Message.Body.PaymentDetailsReq);

	exiIn.V2G_Message.Body.PaymentDetailsReq.eMAID.characters[0] = 1;
	exiIn.V2G_Message.Body.PaymentDetailsReq.eMAID.characters[1] = 123;
	exiIn.V2G_Message.Body.PaymentDetailsReq.eMAID.charactersLen =2;

	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Certificate.bytes[0] = 'C';
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Certificate.bytes[1] = 'e';
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Certificate.bytesLen = 2;
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates_isUsed = 1u;
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytes[0] = 'S';
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytes[1] = 'u';
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytesLen = 2;
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[1].bytes[0] = 'S';
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[1].bytes[1] = 'u';
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[1].bytes[2] = '2';
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[1].bytesLen = 3;
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.arrayLen =2;
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Id_isUsed = 1u;
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Id.charactersLen = 2;
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Id.characters[0] = 'I';
	exiIn.V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Id.characters[0] = 'd';

	printf("EV side: call EVSE ServiceDetail \n");

	errn = request_response2(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.PaymentDetailsRes_isUsed) {

			paymentDetailsRes = exiOut.V2G_Message.Body.PaymentDetailsRes;

			printf("EV side: received response message from EVSE\n");
			/* show results of EVSEs answer message */
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n",  paymentDetailsRes.ResponseCode);
			printf("\tEVSETimeStamp=%li\n",  (long int) paymentDetailsRes.EVSETimeStamp);
			printf("\tGenChallenge=%d\n",   paymentDetailsRes.GenChallenge.bytes[0]);

		} else {
			errn = ERROR_UNEXPECTED_PAYMENT_DETAILS_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}




	/*******************************************
	 * Authorization *
	 *******************************************/
	init_iso2BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.AuthorizationReq_isUsed = 1u;

	init_iso2AuthorizationReqType(&exiIn.V2G_Message.Body.AuthorizationReq);

	copyBytes(paymentDetailsRes.GenChallenge.bytes, paymentDetailsRes.GenChallenge.bytesLen, exiIn.V2G_Message.Body.AuthorizationReq.GenChallenge.bytes);
	exiIn.V2G_Message.Body.AuthorizationReq.GenChallenge.bytesLen = paymentDetailsRes.GenChallenge.bytesLen;
	exiIn.V2G_Message.Body.AuthorizationReq.GenChallenge_isUsed = 1u; /* no challenge needed here*/
	exiIn.V2G_Message.Body.AuthorizationReq.Id_isUsed = 1u; /* no signature needed here */
	exiIn.V2G_Message.Body.AuthorizationReq.Id.charactersLen = 3;
	exiIn.V2G_Message.Body.AuthorizationReq.Id.characters[0] = 'I';
	exiIn.V2G_Message.Body.AuthorizationReq.Id.characters[1] = 'd';
	exiIn.V2G_Message.Body.AuthorizationReq.Id.characters[2] = '2';

	printf("EV side: call EVSE Authorization \n");


	errn = request_response2(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.AuthorizationRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n",  exiOut.V2G_Message.Body.AuthorizationRes.ResponseCode);

			if(exiOut.V2G_Message.Body.AuthorizationRes.EVSEProcessing == iso2EVSEProcessingType_Finished) {
				printf("\t EVSEProcessing=Finished\n");
			}
		} else {
			errn = ERROR_UNEXPECTED_AUTHORIZATION_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}




	/*******************************************
	 * chargeParameterDiscovery *
	 *******************************************/
	init_iso2BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed = 1u;

	init_iso2ChargeParameterDiscoveryReqType(&exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq);

	/* we use here AC based charging parameters */
	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.MaxSupportingPoints_isUsed = 1u;
	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.MaxSupportingPoints = 1234;

	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter_isUsed = 1u;
	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.DepartureTime = 12345;

	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMaximumChargePower.Exponent = 0;
	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMaximumChargePower.Value = 100;

	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMaximumChargeCurrent.Exponent = 0;
	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMaximumChargeCurrent.Value = 400;

	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMinimumChargeCurrent.Exponent = 0;
	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMinimumChargeCurrent.Value = 200;

	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMaximumVoltage.Exponent = 0;
	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMaximumVoltage.Value = 400;

	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMaximumDischargePower.Exponent = 0;
	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMaximumDischargePower.Value = 200;

	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMaximumDischargeCurrent.Exponent = 0;
	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMaximumDischargeCurrent.Value = 400;

	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMinimumDischargeCurrent.Exponent = 0;
	exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMinimumDischargeCurrent.Value = 200;

	printf("EV side: call EVSE chargeParameterDiscovery");

	errn = request_response2(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n", exiOut.V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode);

			/*printACEVSEStatus(&(exiOut.V2G_Message.Body.ChargeParameterDiscoveryRes.AC_EVSEChargeParameter.AC_EVSEStatus));
			printf("\t EVSEProcessing=%d\n", exiOut.V2G_Message.Body.ChargeParameterDiscoveryRes.EVSEProcessing);
			printf("\t EVSEMaxCurrent=%d\n", exiOut.V2G_Message.Body.ChargeParameterDiscoveryRes.AC_EVSEChargeParameter.EVSEMaxCurrent.Value);
			printf("\t EVSENominalVoltage=%d\n", exiOut.V2G_Message.Body.ChargeParameterDiscoveryRes.AC_EVSEChargeParameter.EVSENominalVoltage.Value);*/
		} else {
			errn = ERROR_UNEXPECTED_CHARGE_PARAMETER_DISCOVERY_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}





	/*****************************
	 * cableCheck *
	 *****************************/
	init_iso2BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.CableCheckReq_isUsed = 1u;

	/*init_v2gCableCheckReqType(&exiIn.V2G_Message.Body.CableCheckReq);*/

	printf("EV side: call EVSE cableCheck \n");

	errn = request_response2(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.CableCheckRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n", exiOut.V2G_Message.Body.CableCheckRes.ResponseCode);

			if(exiOut.V2G_Message.Body.CableCheckRes.EVSEProcessing==iso2EVSEProcessingType_Finished) {
				printf("\tEVSEProcessing=Finished\n");
			}

			printEVSEStatus2(&(exiOut.V2G_Message.Body.CableCheckRes.EVSEStatus));
		} else {
			errn = ERROR_UNEXPECTED_CABLE_CHECK_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}



	/*****************************
	 * preCharge *
	 *****************************/
	init_iso2BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.PreChargeReq_isUsed = 1u;

	init_iso2PreChargeReqType(&exiIn.V2G_Message.Body.PreChargeReq);

	exiIn.V2G_Message.Body.PreChargeReq.EVTargetCurrent.Exponent = 1;
	exiIn.V2G_Message.Body.PreChargeReq.EVTargetCurrent.Value = 234;

	exiIn.V2G_Message.Body.PreChargeReq.EVTargetVoltage.Exponent = 1;
	exiIn.V2G_Message.Body.PreChargeReq.EVTargetVoltage.Value = 100;

	printf("EV side: call EVSE preCharge \n");

	errn = request_response2(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.PreChargeRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n", exiOut.V2G_Message.Body.PreChargeRes.ResponseCode);

			printEVSEStatus2(&exiOut.V2G_Message.Body.PreChargeRes.EVSEStatus);
			printf("\tEVSEPresentVoltage=%d (%d %d)\n", exiOut.V2G_Message.Body.PreChargeRes.EVSEPresentVoltage.Value, exiOut.V2G_Message.Body.PreChargeRes.EVSEPresentVoltage.Value, exiOut.V2G_Message.Body.PreChargeRes.EVSEPresentVoltage.Exponent);

		} else {
			errn = ERROR_UNEXPECTED_PRE_CHARGE_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}



	/*********************************
	 * PowerDelivery *
	 *********************************/

	init_iso2BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.PowerDeliveryReq_isUsed = 1u;

	init_iso2PowerDeliveryReqType(&exiIn.V2G_Message.Body.PowerDeliveryReq);

	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargeProgress = iso2chargeProgressType_Start;
	exiIn.V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID_isUsed = 1u;
	exiIn.V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID = exiOut.V2G_Message.Body.ChargeParameterDiscoveryRes.SAScheduleList.SAScheduleTuple.array[0].SAScheduleTupleID;

	printf("EV side: call EVSE powerDelivery \n");

	errn = request_response2(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.PowerDeliveryRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n", exiOut.V2G_Message.Body.PowerDeliveryRes.ResponseCode);

			/*printACEVSEStatus(&(exiOut.V2G_Message.Body.PowerDeliveryRes.AC_EVSEStatus));*/
		} else {
			errn = ERROR_UNEXPECTED_POWER_DELIVERY_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}



	/*********************************
	 * Setup data for chargingStatus *
	 *********************************/

	init_iso2BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.ChargingStatusReq_isUsed = 1u;

	init_iso2ChargingStatusReqType(&exiIn.V2G_Message.Body.ChargingStatusReq);
	exiIn.V2G_Message.Body.ChargingStatusReq.EVTargetEnergyRequest.Exponent = 2;
	exiIn.V2G_Message.Body.ChargingStatusReq.EVTargetEnergyRequest.Value = 100;

	printf("EV side: call EVSE chargingStatus \n");

	errn = request_response2(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.ChargingStatusRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n", exiOut.V2G_Message.Body.ChargingStatusRes.ResponseCode);

			/*printACEVSEStatus(&(exiOut.V2G_Message.Body.ChargingStatusRes.AC_EVSEStatus));

			printf("\tReceiptRequired=%d\n", exiOut.V2G_Message.Body.ChargingStatusRes.ReceiptRequired);
			printf("\tEVSEID=%d\n", exiOut.V2G_Message.Body.ChargingStatusRes.EVSEID.characters[0]);
			printf("\tSAScheduleTupleID=%d\n", exiOut.V2G_Message.Body.ChargingStatusRes.SAScheduleTupleID);
			printf("\tEVSEMaxCurrent=%d (%d %d)\n", exiOut.V2G_Message.Body.ChargingStatusRes.EVSEMaxCurrent.Value, exiOut.V2G_Message.Body.ChargingStatusRes.EVSEMaxCurrent.Unit, exiOut.V2G_Message.Body.ChargingStatusRes.EVSEMaxCurrent.Multiplier);
			printf("\tisused.MeterInfo=%d\n",		exiOut.V2G_Message.Body.ChargingStatusRes.MeterInfo_isUsed);
			printf("\t\tMeterInfo.MeterID=%d\n",		exiOut.V2G_Message.Body.ChargingStatusRes.MeterInfo.MeterID.characters[0]);
			printf("\t\tMeterInfo.MeterReading.Value=%li\n",		(long int)exiOut.V2G_Message.Body.ChargingStatusRes.MeterInfo.MeterReading);
			printf("\t\tMeterInfo.MeterStatus=%d\n",		exiOut.V2G_Message.Body.ChargingStatusRes.MeterInfo.MeterStatus);
			printf("\t\tMeterInfo.TMeter=%li\n",		(long int)exiOut.V2G_Message.Body.ChargingStatusRes.MeterInfo.TMeter);
			printf("\t\tMeterInfo.SigMeterReading.data=%d\n",		exiOut.V2G_Message.Body.ChargingStatusRes.MeterInfo.SigMeterReading.bytes[0]);*/
		} else {
			errn = ERROR_UNEXPECTED_CHARGING_STATUS_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}




	/***********************************
	 * MeteringReceipt *
	 ***********************************/

	init_iso2BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.MeteringReceiptReq_isUsed = 1u;

	init_iso2MeteringReceiptReqType(&exiIn.V2G_Message.Body.MeteringReceiptReq);


	exiIn.V2G_Message.Body.MeteringReceiptReq.Id.characters[0]='I';
	exiIn.V2G_Message.Body.MeteringReceiptReq.Id.characters[1]='d';
	exiIn.V2G_Message.Body.MeteringReceiptReq.Id.characters[2]='3';
	exiIn.V2G_Message.Body.MeteringReceiptReq.Id.charactersLen =3;

	exiIn.V2G_Message.Body.MeteringReceiptReq.SessionID.bytes[0] = 22;
	exiIn.V2G_Message.Body.MeteringReceiptReq.SessionID.bytesLen = 1;

	init_iso2MeterInfoType(&exiIn.V2G_Message.Body.MeteringReceiptReq.MeterInfo);
	exiIn.V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterID.characters[0] = 'M';
	exiIn.V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterID.characters[1] = 'i';
	exiIn.V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterID.characters[2] = 'd';
	exiIn.V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterID.charactersLen = 3;

	printf("EV side: call EVSE meteringReceipt \n");

	errn = request_response2(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.MeteringReceiptRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n", exiOut.V2G_Message.Body.MeteringReceiptRes.ResponseCode);

		} else {
			errn = ERROR_UNEXPECTED_METERING_RECEIPT_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}



	/***********************************
	 * SessionStop *
	 ***********************************/


	init_iso2BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.SessionStopReq_isUsed = 1u;

	init_iso2SessionStopReqType(&exiIn.V2G_Message.Body.SessionStopReq);
	exiIn.V2G_Message.Body.SessionStopReq.ChargingSession = iso2chargingSessionType_Pause;

	printf("EV side: call EVSE stopSession \n");

	errn = request_response2(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.SessionStopRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n", exiOut.V2G_Message.Body.SessionStopRes.ResponseCode);

		} else {
			errn = ERROR_UNEXPECTED_SESSION_STOP_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}



	return errn;

}
#endif /* DEPLOY_ISO2_CODEC == SUPPORT_YES */






#if DEPLOY_ISO1_CODEC == SUPPORT_YES

static void printEVSEStatus1(struct iso1DC_EVSEStatusType* status)
{
	printf("\tEVSEStatus:\n");
	printf("\t\tEVSENotification=%d\n", status->EVSENotification);
	printf("\t\tNotificationMaxDelay=%d\n", status->NotificationMaxDelay);
}


/**
 * Serializes an ISO1 EXI document into a bitstream for transmission.
 * This function encodes the input ISO1 EXI document into the provided bitstream
 * and adds the V2GTP header for EXI data type.
 *
 * @param exiIn Pointer to the ISO1 EXI document to be serialized.
 * @param stream Pointer to the bitstream where the serialized data will be stored.
 * @return 0 on success, or an error code indicating failure.
 */
static int serialize1EXI2Stream(struct iso1EXIDocument* exiIn, bitstream_t* stream) {
	int errn;
	*stream->pos = V2GTP_HEADER_LENGTH;  /* v2gtp header */
	if( (errn = encode_iso1ExiDocument(stream, exiIn)) == 0) {
		errn = write_v2gtpHeader(stream->data, (*stream->pos)-V2GTP_HEADER_LENGTH, V2GTP_EXI_TYPE);
	}
	return errn;
}



/**
 * Deserializes an EXI-encoded bitstream into an ISO1 EXI document.
 * This function reads an EXI-encoded bitstream, extracts the ISO1 EXI document,
 * and decodes it into the provided ISO1 EXI document structure.
 *
 * @param streamIn Pointer to the input bitstream containing the EXI-encoded data.
 * @param exi Pointer to the ISO1 EXI document structure where the decoded data will be stored.
 * @return 0 on success, or an error code indicating failure.
 */
static int deserialize1Stream2EXI(bitstream_t* streamIn, struct iso1EXIDocument* exi) {
	int errn;
	uint32_t payloadLength;

	*streamIn->pos = 0;
	if ( (errn = read_v2gtpHeader(streamIn->data, &payloadLength)) == 0) {
		*streamIn->pos += V2GTP_HEADER_LENGTH;

		errn = decode_iso1ExiDocument(streamIn, exi);
	}
	return errn;
}




/**
 * Sends a request to the server and receives a response using the ISO1 protocol.
 * This function serializes the input EXI document, sends it to the server, receives the response,
 * and deserializes it into the output EXI document.
 *
 * @param exiIn Pointer to the input EXI document to be sent.
 * @param exiOut Pointer to the output EXI document to store the response.
 * @return 0 on success, or an error code indicating failure.
 */
static int request_response1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut) {
	int errn;
	bitstream_t stream1;
	bitstream_t stream2;
	size_t pos1;
	size_t pos2;

	stream1.size = BUFFER_SIZE;
	stream1.data = buffer1;
	stream1.pos = &pos1;

	stream2.size = BUFFER_SIZE;
	stream2.data = buffer2;
	stream2.pos = &pos2;

	/* EV side */
	errn = serialize1EXI2Stream(exiIn, &stream1);

	if(errn == 0){
		errn = send2server(&stream1, &stream2);
	}


	if (errn == 0) {
		errn = deserialize1Stream2EXI(&stream2, exiOut);
	}
	return errn;
}

/**
 * Initiates the V2G client/service example for charging (ISO1).
 * This function handles the V2G communication protocol for charging, including session setup,
 * service details, authorization, cable check, pre-charge, power delivery, charging status, and session stop.
 *
 * @return 0 on success, or an error code indicating failure.
 */
int charging1()
{
	int errn = 0;
	int i, j;

	struct iso1EXIDocument exiIn;
	struct iso1EXIDocument exiOut;

	struct iso1ServiceDetailResType serviceDetailRes;
	struct iso1PaymentDetailsResType paymentDetailsRes;

	/* setup header information */
	init_iso1EXIDocument(&exiIn);
	exiIn.V2G_Message_isUsed = 1u;
	init_iso1MessageHeaderType(&exiIn.V2G_Message.Header);
	exiIn.V2G_Message.Header.SessionID.bytes[0] = 0; /* sessionID is always '0' at the beginning (the response contains the valid sessionID)*/
	exiIn.V2G_Message.Header.SessionID.bytes[1] = 0;
	exiIn.V2G_Message.Header.SessionID.bytes[2] = 0;
	exiIn.V2G_Message.Header.SessionID.bytes[3] = 0;
	exiIn.V2G_Message.Header.SessionID.bytes[4] = 0;
	exiIn.V2G_Message.Header.SessionID.bytes[5] = 0;
	exiIn.V2G_Message.Header.SessionID.bytes[6] = 0;
	exiIn.V2G_Message.Header.SessionID.bytes[7] = 0;
	exiIn.V2G_Message.Header.SessionID.bytesLen = 8;
	exiIn.V2G_Message.Header.Signature_isUsed = 0u;


	/************************
	 * sessionSetup *
	 ************************/
	init_iso1BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.SessionSetupReq_isUsed = 1u;

	init_iso1SessionSetupReqType(&exiIn.V2G_Message.Body.SessionSetupReq);

	exiIn.V2G_Message.Body.SessionSetupReq.EVCCID.bytesLen = 1;
	exiIn.V2G_Message.Body.SessionSetupReq.EVCCID.bytes[0] = 10;

	printf("EV side: call EVSE sessionSetup");

	errn = request_response1(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.SessionSetupRes_isUsed) {
			/* show results of EVSEs answer message */
			init_iso1MessageHeaderType(&exiIn.V2G_Message.Header);
			exiIn.V2G_Message.Header.SessionID.bytes[0] = exiOut.V2G_Message.Header.SessionID.bytes[0];
			exiIn.V2G_Message.Header.SessionID.bytes[1] = exiOut.V2G_Message.Header.SessionID.bytes[1];
			exiIn.V2G_Message.Header.SessionID.bytes[2] = exiOut.V2G_Message.Header.SessionID.bytes[2];
			exiIn.V2G_Message.Header.SessionID.bytes[3] = exiOut.V2G_Message.Header.SessionID.bytes[3];
			exiIn.V2G_Message.Header.SessionID.bytes[4] = exiOut.V2G_Message.Header.SessionID.bytes[4];
			exiIn.V2G_Message.Header.SessionID.bytes[5] = exiOut.V2G_Message.Header.SessionID.bytes[5];
			exiIn.V2G_Message.Header.SessionID.bytes[6] = exiOut.V2G_Message.Header.SessionID.bytes[6];
			exiIn.V2G_Message.Header.SessionID.bytes[7] = exiOut.V2G_Message.Header.SessionID.bytes[7];
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\tResponseCode=%d\n", exiOut.V2G_Message.Body.SessionSetupRes.ResponseCode);
			printf("\tEVSEID=%d\n",	exiOut.V2G_Message.Body.SessionSetupRes.EVSEID.characters[1]);
			printf("\tEVSETimeStamp=%li\n", (long int)exiOut.V2G_Message.Body.SessionSetupRes.EVSETimeStamp);
		} else {
			errn = ERROR_UNEXPECTED_SESSION_SETUP_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}



	/*********************************
	 * ServiceDetails *
	 *********************************/
	
	init_iso1BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.ServiceDetailReq_isUsed = 1u;

	init_iso1ServiceDetailReqType(&exiIn.V2G_Message.Body.ServiceDetailReq);

	exiIn.V2G_Message.Body.ServiceDetailReq.ServiceID = 22; /* Value Added Server ID */

	printf("EV side: call EVSE ServiceDetail \n");

	errn = request_response1(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.ServiceDetailRes_isUsed) {
			serviceDetailRes = exiOut.V2G_Message.Body.ServiceDetailRes;
			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n",  exiOut.V2G_Message.Body.ServiceDiscoveryRes.ResponseCode);
			printf("\t ServiceID=%d\n",	exiOut.V2G_Message.Body.ServiceDetailRes.ServiceID);

			if(serviceDetailRes.ServiceParameterList_isUsed) {
				printf("\t\tLength=%d\n", serviceDetailRes.ServiceParameterList.ParameterSet.arrayLen );/*TEST*/

				for(i=0; i<serviceDetailRes.ServiceParameterList.ParameterSet.arrayLen; i++)
				{
					printf("\t\tServiceSetID=%d\n", serviceDetailRes.ServiceParameterList.ParameterSet.array[i].ParameterSetID);
					printf("\t\tParameters=%d\n", serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.arrayLen);

					for(j=0; j<serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.arrayLen; j++)
					{
						printf("\t\t\t %d: ParameterName=", j+1);
						printASCIIString(serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].Name.characters, exiOut.V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].Name.charactersLen);

						/*if(serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].shortValue_isUsed == 1u) {
							printf("\t\t\t %d: StringValue=", j+1);
							printASCIIString(serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].stringValue.characters, serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].stringValue.charactersLen);
						} else if(serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].intValue_isUsed == 1u) {
							printf("\t\t\t %d: IntValue=%d\n", j+1, serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].intValue);
						} else if(serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].physicalValue_isUsed == 1u) {
							printf("\t\t\t %d: PhysicalValue=%d (%d)\n",  j+1, serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].physicalValue.Value, serviceDetailRes.ServiceParameterList.ParameterSet.array[i].Parameter.array[j].physicalValue.Multiplier);
						}*/
					}
				}
			}
		} else {
			errn = ERROR_UNEXPECTED_SERVICE_DETAILS_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}




	/*******************************************
	 * Authorization *
	 *******************************************/
	init_iso1BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.AuthorizationReq_isUsed = 1u;

	init_iso1AuthorizationReqType(&exiIn.V2G_Message.Body.AuthorizationReq);

	copyBytes(paymentDetailsRes.GenChallenge.bytes, paymentDetailsRes.GenChallenge.bytesLen, exiIn.V2G_Message.Body.AuthorizationReq.GenChallenge.bytes);
	exiIn.V2G_Message.Body.AuthorizationReq.GenChallenge.bytesLen = paymentDetailsRes.GenChallenge.bytesLen;
	exiIn.V2G_Message.Body.AuthorizationReq.GenChallenge_isUsed = 1u; /* no challenge needed here*/
	exiIn.V2G_Message.Body.AuthorizationReq.Id_isUsed = 1u; /* no signature needed here */
	exiIn.V2G_Message.Body.AuthorizationReq.Id.charactersLen = 3;
	exiIn.V2G_Message.Body.AuthorizationReq.Id.characters[0] = 'I';
	exiIn.V2G_Message.Body.AuthorizationReq.Id.characters[1] = 'd';
	exiIn.V2G_Message.Body.AuthorizationReq.Id.characters[2] = '2';

	printf("EV side: call EVSE Authorization \n");


	errn = request_response1(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.AuthorizationRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n",  exiOut.V2G_Message.Body.AuthorizationRes.ResponseCode);

			if(exiOut.V2G_Message.Body.AuthorizationRes.EVSEProcessing == iso1EVSEProcessingType_Finished) {
				printf("\t EVSEProcessing=Finished\n");
			}
		} else {
			errn = ERROR_UNEXPECTED_AUTHORIZATION_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}





	/*****************************
	 * cableCheck *
	 *****************************/
	init_iso1BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.CableCheckReq_isUsed = 1u;

	/*init_v2gCableCheckReqType(&exiIn.V2G_Message.Body.CableCheckReq);*/

	printf("EV side: call EVSE cableCheck \n");

	errn = request_response1(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.CableCheckRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n", exiOut.V2G_Message.Body.CableCheckRes.ResponseCode);

			if(exiOut.V2G_Message.Body.CableCheckRes.EVSEProcessing==iso1EVSEProcessingType_Finished) {
				printf("\tEVSEProcessing=Finished\n");
			}

			printEVSEStatus1(&(exiOut.V2G_Message.Body.CableCheckRes.DC_EVSEStatus));
		} else {
			errn = ERROR_UNEXPECTED_CABLE_CHECK_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}



	/*****************************
	 * preCharge *
	 *****************************/
	init_iso1BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.PreChargeReq_isUsed = 1u;

	init_iso1PreChargeReqType(&exiIn.V2G_Message.Body.PreChargeReq);

	exiIn.V2G_Message.Body.PreChargeReq.EVTargetCurrent.Multiplier = 1;
	exiIn.V2G_Message.Body.PreChargeReq.EVTargetCurrent.Value = 234;

	exiIn.V2G_Message.Body.PreChargeReq.EVTargetVoltage.Multiplier = 1;
	exiIn.V2G_Message.Body.PreChargeReq.EVTargetVoltage.Value = 100;

	printf("EV side: call EVSE preCharge \n");

	errn = request_response1(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.PreChargeRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n", exiOut.V2G_Message.Body.PreChargeRes.ResponseCode);

			printEVSEStatus1(&exiOut.V2G_Message.Body.PreChargeRes.DC_EVSEStatus);
			printf("\tEVSEPresentVoltage=%d (%d %d)\n", exiOut.V2G_Message.Body.PreChargeRes.EVSEPresentVoltage.Value, exiOut.V2G_Message.Body.PreChargeRes.EVSEPresentVoltage.Value, exiOut.V2G_Message.Body.PreChargeRes.EVSEPresentVoltage.Multiplier);

		} else {
			errn = ERROR_UNEXPECTED_PRE_CHARGE_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}



	/*********************************
	 * PowerDelivery *
	 *********************************/

	init_iso1BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.PowerDeliveryReq_isUsed = 1u;

	init_iso1PowerDeliveryReqType(&exiIn.V2G_Message.Body.PowerDeliveryReq);

	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargeProgress = iso1chargeProgressType_Start;
	exiIn.V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID = exiOut.V2G_Message.Body.ChargeParameterDiscoveryRes.SAScheduleList.SAScheduleTuple.array[0].SAScheduleTupleID;

	printf("EV side: call EVSE powerDelivery \n");

	errn = request_response1(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.PowerDeliveryRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n", exiOut.V2G_Message.Body.PowerDeliveryRes.ResponseCode);

			/*printACEVSEStatus(&(exiOut.V2G_Message.Body.PowerDeliveryRes.AC_EVSEStatus));*/
		} else {
			errn = ERROR_UNEXPECTED_POWER_DELIVERY_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}



	/*********************************
	 * Setup data for chargingStatus *
	 *********************************/

	init_iso1BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.ChargingStatusReq_isUsed = 1u;

	init_iso1ChargingStatusReqType(&exiIn.V2G_Message.Body.ChargingStatusReq);

	printf("EV side: call EVSE chargingStatus \n");

	errn = request_response1(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.ChargingStatusRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n", exiOut.V2G_Message.Body.ChargingStatusRes.ResponseCode);

			/*printACEVSEStatus(&(exiOut.V2G_Message.Body.ChargingStatusRes.AC_EVSEStatus));

			printf("\tReceiptRequired=%d\n", exiOut.V2G_Message.Body.ChargingStatusRes.ReceiptRequired);
			printf("\tEVSEID=%d\n", exiOut.V2G_Message.Body.ChargingStatusRes.EVSEID.characters[0]);
			printf("\tSAScheduleTupleID=%d\n", exiOut.V2G_Message.Body.ChargingStatusRes.SAScheduleTupleID);
			printf("\tEVSEMaxCurrent=%d (%d %d)\n", exiOut.V2G_Message.Body.ChargingStatusRes.EVSEMaxCurrent.Value, exiOut.V2G_Message.Body.ChargingStatusRes.EVSEMaxCurrent.Unit, exiOut.V2G_Message.Body.ChargingStatusRes.EVSEMaxCurrent.Multiplier);
			printf("\tisused.MeterInfo=%d\n",		exiOut.V2G_Message.Body.ChargingStatusRes.MeterInfo_isUsed);
			printf("\t\tMeterInfo.MeterID=%d\n",		exiOut.V2G_Message.Body.ChargingStatusRes.MeterInfo.MeterID.characters[0]);
			printf("\t\tMeterInfo.MeterReading.Value=%li\n",		(long int)exiOut.V2G_Message.Body.ChargingStatusRes.MeterInfo.MeterReading);
			printf("\t\tMeterInfo.MeterStatus=%d\n",		exiOut.V2G_Message.Body.ChargingStatusRes.MeterInfo.MeterStatus);
			printf("\t\tMeterInfo.TMeter=%li\n",		(long int)exiOut.V2G_Message.Body.ChargingStatusRes.MeterInfo.TMeter);
			printf("\t\tMeterInfo.SigMeterReading.data=%d\n",		exiOut.V2G_Message.Body.ChargingStatusRes.MeterInfo.SigMeterReading.bytes[0]);*/
		} else {
			errn = ERROR_UNEXPECTED_CHARGING_STATUS_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}


	/***********************************
	 * SessionStop *
	 ***********************************/


	init_iso1BodyType(&exiIn.V2G_Message.Body);
	exiIn.V2G_Message.Body.SessionStopReq_isUsed = 1u;

	init_iso1SessionStopReqType(&exiIn.V2G_Message.Body.SessionStopReq);
	exiIn.V2G_Message.Body.SessionStopReq.ChargingSession = iso1chargingSessionType_Pause;

	printf("EV side: call EVSE stopSession \n");

	errn = request_response1(&exiIn, &exiOut);

	if(errn == 0) {
		/* check, if this is the right response message */
		if(exiOut.V2G_Message.Body.SessionStopRes_isUsed) {

			/* show results of EVSEs answer message */
			printf("EV side: received response message from EVSE\n");
			printf("\tHeader SessionID=");
			printBinaryArray(exiOut.V2G_Message.Header.SessionID.bytes, exiOut.V2G_Message.Header.SessionID.bytesLen);
			printf("\t ResponseCode=%d\n", exiOut.V2G_Message.Body.SessionStopRes.ResponseCode);

		} else {
			errn = ERROR_UNEXPECTED_SESSION_STOP_RESP_MESSAGE;
			return errn;
		}
	} else {
		return errn;
	}



	return errn;

}
#endif /* DEPLOY_ISO1_CODEC == SUPPORT_YES */

/**
 * @brief Performs a bidirectional shutdown of the SSL/TLS connection and cleans up associated resources.
 *
 * This function initiates the shutdown process for the SSL/TLS connection and performs cleanup operations
 * on the SSL/TLS objects, context, and socket used for the connection. It ensures that the connection is properly
 * closed and resources are freed.
 *
 * @return 0 on success, or a negative error code indicating failure.
 */
int shutdown_connection() {
	int errn;
	/* Bidirectional shutdown */
    while (errn = wolfSSL_shutdown(ssl) == WOLFSSL_SHUTDOWN_NOT_DONE) {
        printf("Shutdown not complete\n");
    }
    printf("Shutdown complete\n");

    /* Cleanup and return */
cleanup:
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
    close(sockfd);          /* Close the connection to the server       */
    return errn;               /* Return reporting a success               */
}





