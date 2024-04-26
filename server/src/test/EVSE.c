
#include "EVSE.h"
#define BUFFER_SIZE 256 
uint8_t buffer1[BUFFER_SIZE];
uint8_t buffer2[BUFFER_SIZE];
unsigned char buff[BUFFER_SIZE];
int countcase = 0;
int finished = 0;
#if DEPLOY_ISO1_CODEC == SUPPORT_YES
struct iso1EXIDocument exiIn1;
struct iso1EXIDocument exiOut1;
struct iso1ServiceDetailResType serviceDetailRes1;
struct iso1PaymentDetailsResType paymentDetailsRes1;
#endif /* DEPLOY_ISO1_CODEC == SUPPORT_YES */


#if DEPLOY_ISO2_CODEC == SUPPORT_YES
struct iso2EXIDocument exiIn2;
struct iso2EXIDocument exiOut2;

struct iso2ServiceDetailResType serviceDetailRes2;
struct iso2PaymentServiceSelectionResType paymentServiceSelectionRes;
struct iso2PaymentDetailsResType paymentDetailsRes2;
#endif /* DEPLOY_ISO2_CODEC == SUPPORT_YES */

/**
 * @brief Writes the response to the client.
 *
 * This function writes the response contained in `stream2` to the client socket.
 * It copies the data from `stream2->data` to the `buff` buffer and then writes
 * the entire message to the client socket using the WolfSSL library.
 *
 * @param stream2 Pointer to the bitstream containing the response data.
 * @return Returns the number of bytes written on success, or an error code indicating the failure.
 */
int write_response(WOLFSSL *ssl, bitstream_t* stream2) {
    int ret = 0;
    size_t len = stream2->size;

    // Initialize buffer
    memset(buff, 0, sizeof(buff));

    // Copy data from stream2 to buffer
    memcpy(buff, stream2->data, len);

    // Write data to the client
    ret = wolfSSL_write(ssl, buff, len);
    if (ret != len) {
        fprintf(stderr, "ERROR: failed to write\n");
        fprintf(stderr, "ERROR: failed to write entire message\n");
        fprintf(stderr, "%d bytes of %d bytes were sent", ret, (int)len);
        return -1;
    }

    return ret;
}

static int writeStringToEXIString(char* string, exi_string_character_t* exiString) {
	int pos = 0;
	while(string[pos]!='\0')
	{
		exiString[pos] = string[pos];
		pos++;
	}

	return pos;
}

static void printASCIIString(exi_string_character_t* string, uint16_t len) {
	unsigned int i;
	for(i=0; i<len; i++) {
		printf("%c",(char)string[i]);
	}
	printf("\n");
}


static void printBinaryArray(uint8_t* byte, uint16_t len) {
	unsigned int i;
	for(i=0; i<len; i++) {
		printf("%d ",byte[i]);
	}
	printf("\n");
}

static void copyBytes(uint8_t* from, uint16_t len, uint8_t* to) {
	int i;
	for(i=0; i<len; i++) {
		to[i] = from[i];
	}
}


/** Example implementation of the app handshake protocol for the EVSE side  */
static int appHandshakeHandler(bitstream_t* iStream, bitstream_t* oStream) {
	struct appHandEXIDocument appHandResp;
	int i;
	struct appHandEXIDocument exiDoc;
	int errn = 0;
	uint32_t payloadLengthDec;
	if ( (errn = read_v2gtpHeader(iStream->data, &payloadLengthDec)) == 0) {
		*iStream->pos = V2GTP_HEADER_LENGTH;
		if( (errn = decode_appHandExiDocument(iStream, &exiDoc)) ) {
			/* an error occured */
			return errn;
		}
	}
	printf("EVSE side: List of application handshake protocols of the EV \n");
	for(i=0;i<exiDoc.supportedAppProtocolReq.AppProtocol.arrayLen;i++) {
		printf("\tProtocol entry #=%d\n",(i+1));
		printf("\t\tProtocolNamespace=");
		printASCIIString(exiDoc.supportedAppProtocolReq.AppProtocol.array[i].ProtocolNamespace.characters, exiDoc.supportedAppProtocolReq.AppProtocol.array[i].ProtocolNamespace.charactersLen);
		printf("\t\tVersion=%d.%d\n", exiDoc.supportedAppProtocolReq.AppProtocol.array[i].VersionNumberMajor, exiDoc.supportedAppProtocolReq.AppProtocol.array[i].VersionNumberMinor);
		printf("\t\tSchemaID=%d\n", exiDoc.supportedAppProtocolReq.AppProtocol.array[i].SchemaID);
		printf("\t\tPriority=%d\n", exiDoc.supportedAppProtocolReq.AppProtocol.array[i].Priority);
	}
	/* prepare response handshake response:
	 * it is assumed, we support the 15118 1.0 version :-) */
	init_appHandEXIDocument(&appHandResp);
	appHandResp.supportedAppProtocolRes_isUsed = 1u;
	appHandResp.supportedAppProtocolRes.ResponseCode = appHandresponseCodeType_OK_SuccessfulNegotiation;
	appHandResp.supportedAppProtocolRes.SchemaID = exiDoc.supportedAppProtocolReq.AppProtocol.array[0].SchemaID; /* signal the protocol by the provided schema id*/
	appHandResp.supportedAppProtocolRes.SchemaID_isUsed = 1u;
	*oStream->pos = V2GTP_HEADER_LENGTH;
	if( (errn = encode_appHandExiDocument(oStream, &appHandResp)) == 0) {
		errn = write_v2gtpHeader(oStream->data, (*oStream->pos)-V2GTP_HEADER_LENGTH, V2GTP_EXI_TYPE);
	}
	return errn;
}

/**
 * @brief Handles the application handshake between the EV side and the server.
 *
 * This function processes the application handshake between the Electric Vehicle (EV) side
 * and the server. It reads the application handshake request from `stream1`, generates
 * a response, and writes the response to `stream2`. The function also increments `countcase`
 * to track the progress of the handshake.
 *
 * @param stream1 Pointer to the bitstream containing the application handshake request.
 * @param stream2 Pointer to the bitstream where the response will be written.
 * @return Returns 0 on success, or an error code indicating the failure.
 */
static int appHandshake(bitstream_t* stream1, bitstream_t* stream2)
{
	uint32_t payloadLengthDec;
	size_t pos1 = V2GTP_HEADER_LENGTH; /* v2gtp header */
	size_t pos2 = 0;

	struct appHandEXIDocument handshake;
	struct appHandEXIDocument handshakeResp;

	int errn = 0;

	stream1->size = BUFFER_SIZE;
	stream1->data = buff;
	stream1->pos = &pos1;

	stream2->size = BUFFER_SIZE;
	stream2->data = buffer2;
	stream2->pos = &pos2;

	init_appHandEXIDocument(&handshake);

	printf("EV side: setup data for the supported application handshake request message\n");

	if (errn == 0) {
		/* read app handshake request & generate response */
		errn = appHandshakeHandler(stream1, stream2);
	}
	if (errn == 0){
		countcase++;
	}
	if (errn != 0) {
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
 * @brief Serializes an ISO 2 EXI document into a bitstream.
 * 
 * This function serializes the provided ISO 2 EXI document into the specified bitstream.
 * It first sets the position of the bitstream to account for the V2GTP header, then encodes
 * the EXI document into the stream. Finally, it writes the V2GTP header to the beginning
 * of the stream, indicating the type of data and its length. Error handling is integrated,
 * returning an error code if any operation fails.
 * 
 * @param exiIn Pointer to the ISO 2 EXI document structure to be serialized.
 * @param stream Pointer to the bitstream where the serialized data will be stored.
 * @return An integer representing the error code. Zero indicates success, while non-zero
 * values denote various error conditions.
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
 * @brief Deserializes data from a bitstream into an ISO 2 EXI document structure.
 * 
 * This function deserializes data from the provided bitstream into an ISO 2 EXI document
 * structure. It first reads the V2GTP header from the bitstream to determine the payload
 * length, then decodes the EXI document from the stream. Error handling is integrated,
 * returning an error code if any operation fails.
 * 
 * @param streamIn Pointer to the bitstream containing the serialized data.
 * @param exi Pointer to the ISO 2 EXI document structure to store the deserialized data.
 * @return An integer representing the error code. Zero indicates success, while
 * non-zero values denote various error conditions.
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

static int sessionSetup2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {
	printf("EVSE side: sessionSetup called\n"  );
	printf("\tReceived data:\n");
	printf("\tHeader SessionID=");
	printBinaryArray(exiIn->V2G_Message.Header.SessionID.bytes, exiIn->V2G_Message.Header.SessionID.bytesLen);
	printf("\t\t EVCCID=%d\n", exiIn->V2G_Message.Body.SessionSetupReq.EVCCID.bytes[0]);

	exiOut->V2G_Message_isUsed = 1u;

	/* generate an unique sessionID */
	init_iso2MessageHeaderType(&exiOut->V2G_Message.Header);
	exiOut->V2G_Message.Header.SessionID.bytes[0] = 1;
	exiOut->V2G_Message.Header.SessionID.bytes[1] = 2;
	exiOut->V2G_Message.Header.SessionID.bytes[2] = 3;
	exiOut->V2G_Message.Header.SessionID.bytes[3] = 4;
	exiOut->V2G_Message.Header.SessionID.bytes[4] = 5;
	exiOut->V2G_Message.Header.SessionID.bytes[5] = 6;
	exiOut->V2G_Message.Header.SessionID.bytes[6] = 7;
	exiOut->V2G_Message.Header.SessionID.bytes[7] = 8;
	exiOut->V2G_Message.Header.SessionID.bytesLen = 8;

	/* Prepare data for EV */
	init_iso2BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.SessionSetupRes_isUsed = 1u;
	init_iso2SessionSetupResType(&exiOut->V2G_Message.Body.SessionSetupRes);

	exiOut->V2G_Message.Body.SessionSetupRes.ResponseCode = iso2responseCodeType_OK;
	exiOut->V2G_Message.Body.SessionSetupRes.EVSEID.characters[0] = 0;
	exiOut->V2G_Message.Body.SessionSetupRes.EVSEID.characters[1] = 20;
	exiOut->V2G_Message.Body.SessionSetupRes.EVSEID.charactersLen = 2;
	exiOut->V2G_Message.Body.SessionSetupRes.EVSETimeStamp_isUsed = 1u;
	exiOut->V2G_Message.Body.SessionSetupRes.EVSETimeStamp = 123456789;

	return 0;
}

static int serviceDiscovery2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {
	int i;

	printf("EVSE side: serviceDiscovery called\n"  );
	printf("\tReceived data:\n");
	printf("\tHeader SessionID=");
	printBinaryArray(exiIn->V2G_Message.Header.SessionID.bytes, exiIn->V2G_Message.Header.SessionID.bytesLen);
	if(exiIn->V2G_Message.Body.ServiceDiscoveryReq.SupportedServiceIDs_isUsed) {
		for(i=0;i<exiIn->V2G_Message.Body.ServiceDiscoveryReq.SupportedServiceIDs.ServiceID.arrayLen; i++) {
			printf("\t\tSupportedServiceID=%d\n", exiIn->V2G_Message.Body.ServiceDiscoveryReq.SupportedServiceIDs.ServiceID.array[i]);
		}
	}

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso2BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.ServiceDiscoveryRes_isUsed = 1u;
	init_iso2ServiceDiscoveryResType(&exiOut->V2G_Message.Body.ServiceDiscoveryRes);


	exiOut->V2G_Message.Body.ServiceDiscoveryRes.VASList_isUsed = 0u;  /* we do not provide VAS */
	exiOut->V2G_Message.Body.ServiceDiscoveryRes.ResponseCode = iso2responseCodeType_OK;

	exiOut->V2G_Message.Body.ServiceDiscoveryRes.PaymentOptionList.PaymentOption.array[0] = iso2paymentOptionType_ExternalPayment; /* EVSE handles the payment */
	exiOut->V2G_Message.Body.ServiceDiscoveryRes.PaymentOptionList.PaymentOption.array[1] = iso2paymentOptionType_Contract;
	exiOut->V2G_Message.Body.ServiceDiscoveryRes.PaymentOptionList.PaymentOption.arrayLen = 2;

	exiOut->V2G_Message.Body.ServiceDiscoveryRes.EnergyTransferServiceList.Service.arrayLen = 1;
	exiOut->V2G_Message.Body.ServiceDiscoveryRes.EnergyTransferServiceList.Service.array[0].ServiceID = 1; /* ID of the charge service */
	exiOut->V2G_Message.Body.ServiceDiscoveryRes.EnergyTransferServiceList.Service.array[0].FreeService = 1;

	exiOut->V2G_Message.Body.ServiceDiscoveryRes.VASList_isUsed = 0u; /* no value added service requested */

	return 0;
}


static int serviceDetail2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {

	printf("EVSE side: serviceDetail called\n"  );
	printf("\tReceived data:\n");
	printf("\tHeader SessionID=");
	printBinaryArray(exiIn->V2G_Message.Header.SessionID.bytes, exiIn->V2G_Message.Header.SessionID.bytesLen);
	printf("\t\t ServiceDetailID=%d\n",exiIn->V2G_Message.Body.ServiceDetailReq.ServiceID);


	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso2BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.ServiceDetailRes_isUsed= 1u;
	init_iso2ServiceDetailResType(&exiOut->V2G_Message.Body.ServiceDetailRes);

	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceID = 1234;

	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList_isUsed = 1u;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.arrayLen = 2;

	/* Parameter Set 1*/
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].ParameterSetID = 1;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.arrayLen = 2;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.charactersLen = 8;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[0] = 'P';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[1] = 'r';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[2] = 'o';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[3] = 't';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[4]= 'o';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[5] = 'c';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[6] = 'o';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[7] = 'l';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].intValue = 15119;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].intValue_isUsed = 1u;

	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].Name.charactersLen = 4;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].Name.characters[0] = 'N';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].Name.characters[1] = 'a';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].Name.characters[2] = 'm';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].Name.characters[3] = 'e';

	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].stringValue_isUsed = 1u;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].stringValue.charactersLen = 3;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].stringValue.characters[0] = 'V';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].stringValue.characters[1] = '2';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].stringValue.characters[2] = 'G';

	/* Parameter Set 2 */
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].ParameterSetID = 2;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.arrayLen = 1;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.charactersLen = 7;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[0] = 'C';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[1] = 'h';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[2] = 'a';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[3] = 'n';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[4] = 'n';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[5] = 'e';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[6] = 'l';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].physicalValue_isUsed = 1u;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].physicalValue.Value = 1234;

	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].physicalValue.Exponent = 1;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].physicalValue.Value = 2;

	exiOut->V2G_Message.Body.ServiceDetailRes.ResponseCode = iso2responseCodeType_OK;

	return 0;
}


static int paymentServiceSelection2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {
	int i;

	printf("EVSE side: paymentServiceSelection called\n"  );
	printf("\tReceived data:\n");
	printf("\tHeader SessionID=");
	printBinaryArray(exiIn->V2G_Message.Header.SessionID.bytes, exiIn->V2G_Message.Header.SessionID.bytesLen);

	if(exiIn->V2G_Message.Body.PaymentServiceSelectionReq.SelectedPaymentOption == iso2paymentOptionType_ExternalPayment)  {
		printf("\t\t SelectedPaymentOption=ExternalPayment\n");
	}

	if(exiIn->V2G_Message.Body.PaymentServiceSelectionReq.SelectedVASList_isUsed) {
		for(i=0; i<exiIn->V2G_Message.Body.PaymentServiceSelectionReq.SelectedVASList.SelectedService.arrayLen;i++)
		{
			printf("\t\t ServiceID=%d\n", exiIn->V2G_Message.Body.PaymentServiceSelectionReq.SelectedVASList.SelectedService.array[i].ServiceID);
			printf("\t\t ParameterSetID=%d\n", exiIn->V2G_Message.Body.PaymentServiceSelectionReq.SelectedVASList.SelectedService.array[i].ParameterSetID);
		}
	}

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso2BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.PaymentServiceSelectionRes_isUsed= 1u;
	init_iso2PaymentServiceSelectionResType(&exiOut->V2G_Message.Body.PaymentServiceSelectionRes);

	exiOut->V2G_Message.Body.ServiceDetailRes.ResponseCode = iso2responseCodeType_OK;

	return 0;
}


static int paymentDetails2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {

	printf("EVSE side: paymentDetails called\n"  );
	printf("\tReceived data:\n");

	printf("\t\t eMAID=%d\n", exiIn->V2G_Message.Body.PaymentDetailsReq.eMAID.characters[0]);
	printf("\t\t ID=%c%c\n", exiIn->V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Id.characters[0], exiIn->V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Id.characters[1]);
	printf("\t\t Certificate=%c%c\n", exiIn->V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Certificate.bytes[0],  exiIn->V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.Certificate.bytes[1]);
	printf("\t\t SubCertificate 1=%c%c\n", exiIn->V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytes[0], exiIn->V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytes[1]);
	printf("\t\t SubCertificate 2=%c%c\n", exiIn->V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[1].bytes[0], exiIn->V2G_Message.Body.PaymentDetailsReq.ContractSignatureCertChain.SubCertificates.Certificate.array[1].bytes[1]);

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso2BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.PaymentDetailsRes_isUsed = 1u;
	init_iso2PaymentDetailsResType(&exiOut->V2G_Message.Body.PaymentDetailsRes);

	exiOut->V2G_Message.Body.PaymentDetailsRes.ResponseCode = iso2responseCodeType_OK;
	exiOut->V2G_Message.Body.PaymentDetailsRes.GenChallenge.bytesLen = 1;
	exiOut->V2G_Message.Body.PaymentDetailsRes.GenChallenge.bytes[0] = 1;
	exiOut->V2G_Message.Body.PaymentDetailsRes.EVSETimeStamp = 123456;

	return 0;
}


static int authorization2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {

	printf("EVSE: Authorization called\n"  );
	printf("\tReceived data:\n");

	if(exiIn->V2G_Message.Body.AuthorizationReq.GenChallenge_isUsed) {
		printf("\t\t\t GenChallenge=%d\n", exiIn->V2G_Message.Body.AuthorizationReq.GenChallenge.bytes[0]);
	}
	if(exiIn->V2G_Message.Body.AuthorizationReq.Id_isUsed ) {
		printf("\t\t\t ID=%c%c%c\n", exiIn->V2G_Message.Body.AuthorizationReq.Id.characters[0], exiIn->V2G_Message.Body.AuthorizationReq.Id.characters[1], exiIn->V2G_Message.Body.AuthorizationReq.Id.characters[2]);
	}


	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso2BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.AuthorizationRes_isUsed = 1u;
	init_iso2AuthorizationResType(&exiOut->V2G_Message.Body.AuthorizationRes);

	exiOut->V2G_Message.Body.AuthorizationRes.ResponseCode = iso2responseCodeType_OK;
	exiOut->V2G_Message.Body.AuthorizationRes.EVSEProcessing = iso2EVSEProcessingType_Finished;

	return 0;
}


static int chargeParameterDiscovery2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {

	printf("EVSE side: chargeParameterDiscovery called\n"  );
	printf("\tReceived data:\n");

	if(exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter_isUsed) {
		printf("\t\t DepartureTime=%d\n", exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.DepartureTime);
		printf("\t\t EVMaximumChargeCurrent=%d\n", exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq.AC_EVBidirectionalParameter.EVMaximumChargeCurrent.Value);
	}

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso2BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed = 1u;
	init_iso2ChargeParameterDiscoveryResType(&exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes);

	exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.ResponseCode = iso2responseCodeType_OK_CertificateExpiresSoon;
	exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.EVSEProcessing = iso2EVSEProcessingType_Ongoing;
	exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.EVSEEnergyTransferParameter_isUsed = 1u;
	/*exiOut->V2G_Message.Body.ChargeParameterDiscoveryRes.EVSEEnergyTransferParameter = 0;*/
	return 0;
}


static int powerDelivery2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {
	printf("EVSE side: powerDelivery called\n"  );
	printf("\tReceived data:\n");

	printf("\t\t  ChargeProgress=%d\n", exiIn->V2G_Message.Body.PowerDeliveryReq.ChargeProgress);
	printf("\t\t  SAScheduleTupleID=%d\n", exiIn->V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID);

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso2BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.PowerDeliveryRes_isUsed = 1u;
	init_iso2PowerDeliveryResType(&exiOut->V2G_Message.Body.PowerDeliveryRes);

	exiOut->V2G_Message.Body.PowerDeliveryRes.ResponseCode = iso2responseCodeType_OK;

	exiOut->V2G_Message.Body.PowerDeliveryRes.EVSEStatus_isUsed = 1;
	exiOut->V2G_Message.Body.PowerDeliveryRes.EVSEStatus.EVSENotification = iso2EVSENotificationType_StopCharging;
	exiOut->V2G_Message.Body.PowerDeliveryRes.EVSEStatus.NotificationMaxDelay=12;

	exiOut->V2G_Message.Body.PowerDeliveryRes.EVSEProcessing = iso2EVSEProcessingType_Ongoing_WaitingForCustomerInteraction;

	return 0;
}


static int chargingStatus2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {

	printf("EVSE side: chargingStatus called\n"  );

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso2BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.ChargingStatusRes_isUsed = 1u;
	init_iso2ChargingStatusResType(&exiOut->V2G_Message.Body.ChargingStatusRes);


	exiOut->V2G_Message.Body.ChargingStatusRes.ResponseCode = iso2responseCodeType_OK;
	exiOut->V2G_Message.Body.ChargingStatusRes.EVSEID.characters[0]= 'A';
	exiOut->V2G_Message.Body.ChargingStatusRes.EVSEID.charactersLen =1;

	exiOut->V2G_Message.Body.ChargingStatusRes.EVSEStatus.EVSENotification = iso2EVSENotificationType_ReNegotiation;
	exiOut->V2G_Message.Body.ChargingStatusRes.EVSEStatus.NotificationMaxDelay=123;
	exiOut->V2G_Message.Body.ChargingStatusRes.ReceiptRequired = 1;
	exiOut->V2G_Message.Body.ChargingStatusRes.ReceiptRequired_isUsed = 1;

	return 0;
}


static int meteringReceipt2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {

	printf("EVSE side: meteringReceipt called\n"  );
	printf("\tReceived data:\n");

	printf("\t\t ID=%c%c%c\n", exiIn->V2G_Message.Body.MeteringReceiptReq.Id.characters[0], exiIn->V2G_Message.Body.MeteringReceiptReq.Id.characters[1], exiIn->V2G_Message.Body.MeteringReceiptReq.Id.characters[2]);
	printf("\t\t SAScheduleTupleID=%d\n", exiIn->V2G_Message.Body.MeteringReceiptReq.SAScheduleTupleID);
	printf("\t\t SessionID=%d\n", exiIn->V2G_Message.Body.MeteringReceiptReq.SessionID.bytes[1]);
	printf("\t\t MeterInfo.MeterStatus=%d\n", exiIn->V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterStatus);
	printf("\t\t MeterInfo.MeterID=%d\n",		exiIn->V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterID.characters[0]);

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso2BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.MeteringReceiptRes_isUsed = 1u;
	init_iso2MeteringReceiptResType(&exiOut->V2G_Message.Body.MeteringReceiptRes);

	exiOut->V2G_Message.Body.MeteringReceiptRes.ResponseCode = iso2responseCodeType_FAILED;

	return 0;
}

static int sessionStop2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {

	printf("EVSE side: sessionStop called\n"  );
	printf("\tReceived data:\n");
	printf("\tHeader SessionID=");
	printBinaryArray(exiIn->V2G_Message.Header.SessionID.bytes, exiIn->V2G_Message.Header.SessionID.bytesLen);
	printf("\t\t ChargingSession=%d\n", exiIn->V2G_Message.Body.SessionStopReq.ChargingSession);

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso2BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.SessionStopRes_isUsed = 1u;
	init_iso2SessionStopResType(&exiOut->V2G_Message.Body.SessionStopRes);

	exiOut->V2G_Message.Body.SessionStopRes.ResponseCode = iso2responseCodeType_OK;

	return 0;
}

static int cableCheck2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {

	printf("EVSE side: cableCheck called\n"  );

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso2BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.CableCheckRes_isUsed = 1u;
	init_iso2CableCheckResType(&exiOut->V2G_Message.Body.CableCheckRes);

	exiOut->V2G_Message.Body.CableCheckRes.ResponseCode = iso2responseCodeType_OK;

	exiOut->V2G_Message.Body.CableCheckRes.EVSEStatus.NotificationMaxDelay = 1234;
	exiOut->V2G_Message.Body.CableCheckRes.EVSEStatus.EVSENotification= iso2EVSENotificationType_ReNegotiation;

	exiOut->V2G_Message.Body.CableCheckRes.EVSEProcessing = iso2EVSEProcessingType_Finished;

	return 0;
}

static int preCharge2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {

	printf("EVSE side: preCharge called\n"  );
	printf("\tReceived data:\n");

	printf("\t\t EVTargetCurrent=%d (%d)\n", exiIn->V2G_Message.Body.PreChargeReq.EVTargetCurrent.Value, exiIn->V2G_Message.Body.PreChargeReq.EVTargetCurrent.Exponent);
	printf("\t\t EVTargetVoltage=%d (%d)\n", exiIn->V2G_Message.Body.PreChargeReq.EVTargetVoltage.Value, exiIn->V2G_Message.Body.PreChargeReq.EVTargetVoltage.Exponent);

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso2BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.PreChargeRes_isUsed = 1u;
	init_iso2PreChargeResType(&exiOut->V2G_Message.Body.PreChargeRes);

	exiOut->V2G_Message.Body.PreChargeRes.ResponseCode = iso2responseCodeType_OK;

	exiOut->V2G_Message.Body.PreChargeRes.EVSEStatus.EVSENotification = iso2EVSENotificationType_StopCharging;
	exiOut->V2G_Message.Body.PreChargeRes.EVSEStatus.NotificationMaxDelay= 1234;

	exiOut->V2G_Message.Body.PreChargeRes.EVSEPresentVoltage.Exponent = 3;
	exiOut->V2G_Message.Body.PreChargeRes.EVSEPresentVoltage.Value= 456;

	return 0;
}


/**
 * @brief Creates a response message based on the received request in the ISO 2 EXI format.
 * 
 * This function examines the received ISO 2 EXI request message and generates an appropriate
 * response message. The response message is created based on the type of request received,
 * invoking specific functions to handle different request types. If an unexpected or unsupported
 * request type is encountered, it returns an error code indicating the unexpected request message.
 * 
 * @param exiIn Pointer to the ISO 2 EXI document structure representing the received request.
 * @param exiOut Pointer to the ISO 2 EXI document structure to store the generated response.
 * @return An integer representing the error code. Zero indicates success, while non-zero
 * values denote various error conditions, including encountering an unexpected request message.
 */
static int create_response_message2(struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {
	int errn = ERROR_UNEXPECTED_REQUEST_MESSAGE;

	/* create response message as EXI document */
	if(exiIn->V2G_Message_isUsed) {
		init_iso2EXIDocument(exiOut);
		if (exiIn->V2G_Message.Body.SessionSetupReq_isUsed) {
			errn = sessionSetup2(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.ServiceDiscoveryReq_isUsed) {
			errn = serviceDiscovery2(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.ServiceDetailReq_isUsed) {
			errn = serviceDetail2(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.PaymentServiceSelectionReq_isUsed) {
			errn = paymentServiceSelection2(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.PaymentDetailsReq_isUsed) {
			errn = paymentDetails2(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.AuthorizationReq_isUsed) {
			errn = authorization2(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed) {
			errn = chargeParameterDiscovery2(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.PowerDeliveryReq_isUsed) {
			errn = powerDelivery2(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.ChargingStatusReq_isUsed) {
			errn = chargingStatus2(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.MeteringReceiptReq_isUsed) {
			errn = meteringReceipt2(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.SessionStopReq_isUsed) {
			errn = sessionStop2(exiIn, exiOut);
			finished = 1;
		} else if (exiIn->V2G_Message.Body.CableCheckReq_isUsed) {
			errn = cableCheck2(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.PreChargeReq_isUsed) {
			errn = preCharge2(exiIn, exiOut);
		}
	}

	return errn;
}

/**
 * @brief Performs a request-response operation between two bitstreams.
 * 
 * This function orchestrates a request-response operation between two bitstreams,
 * simulating communication between two systems. It deserializes a request message
 * from one stream, creates a response message, serializes it, and writes it to
 * the other stream. Error handling is integrated throughout the process.
 * 
 * @param stream1 Pointer to the first bitstream representing the sender.
 * @param stream2 Pointer to the second bitstream representing the receiver.
 * @param exiIn Pointer to the EXI document structure for incoming data.
 * @param exiOut Pointer to the EXI document structure for outgoing data.
 * @return An integer representing the error code. Zero indicates success, while
 * non-zero values denote various error conditions.
 */
static int request_response2(bitstream_t* stream1, bitstream_t* stream2 ,struct iso2EXIDocument* exiIn, struct iso2EXIDocument* exiOut) {
	int errn;
	size_t pos2;
	stream2->size = BUFFER_SIZE;
	stream2->data = buffer2;
	stream2->pos = &pos2;

	/* --> Start of EVSE side */
	/* deserialize request message */
	if (errn == 0) {
		errn = deserialize2Stream2EXI(stream1, exiOut);
	}
	/* create response message */
	if (errn == 0) {
		errn = create_response_message2(exiOut, exiIn);
	}
	/* serialize response message */
	if (errn == 0) {
		errn = serialize2EXI2Stream(exiIn, stream2);
	}
	/* <-- End of EVSE side */

	return errn;
}

/**
 * @function charging2
 * @brief Processes a request-response interaction using the provided bitstreams.
 *
 * This function handles the processing of a request-response interaction using the provided bitstreams.
 * It takes in input data from `stream1` and processes the interaction using `request_response2`
 * with the specified encoding (`exiIn2`) and decoding (`exiOut2`) functions. The function returns any
 * error code encountered during the operation.
 *
 * @param stream1 A pointer to a `bitstream_t` structure containing the input data for the request.
 * @param stream2 A pointer to a `bitstream_t` structure to hold the output data for the response.
 *
 * @return int Returns an error code from the request-response interaction. A return value of 0 indicates success.
 */
static int charging2(bitstream_t* stream1, bitstream_t* stream2)
{
	int errn = 0;
	int i, j;

	
	errn = request_response2(stream1, stream2, &exiIn2, &exiOut2);
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
 * @brief Serializes an ISO1 EXI document into a bitstream.
 *
 * This function serializes the ISO1 EXI document `exiIn` into the provided bitstream `stream`.
 * It first sets the position in the bitstream to accommodate the V2GTP header, then encodes the EXI document
 * into the bitstream. After encoding, it writes the V2GTP header at the beginning of the bitstream.
 *
 * @param exiIn Pointer to the ISO1 EXI document to be serialized.
 * @param stream Pointer to the bitstream where the serialized data will be stored.
 * @return Returns 0 on success, or an error code indicating the failure.
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
 * @brief Deserializes a bitstream into an ISO1 EXI document.
 *
 * This function deserializes the data contained in `streamIn` into an ISO1 EXI document
 * structure `exi`. It first reads the V2GTP header from the bitstream to determine the payload
 * length, then decodes the EXI document from the bitstream.
 *
 * @param streamIn Pointer to the bitstream containing the serialized data.
 * @param exi Pointer to the ISO1 EXI document structure for output.
 * @return Returns 0 on success, or an error code indicating the failure.
 */
static int deserialize1Stream2EXI(bitstream_t* streamIn, struct iso1EXIDocument* exi) {
	int errn;
	uint32_t payloadLength;
	// printf("deserialize0");
	*streamIn->pos = 0;
	// printf("deserialize1");
	if ( (errn = read_v2gtpHeader(streamIn->data, &payloadLength)) == 0) {
		// printf("deserialize2");
		*streamIn->pos += V2GTP_HEADER_LENGTH;
		errn = decode_iso1ExiDocument(streamIn, exi);
		// printf("deserialize4");
	}
	return errn;
}



static int sessionSetup1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut) {
	printf("EVSE side: sessionSetup called\n"  );
	printf("\tReceived data:\n");
	printf("\tHeader SessionID=");
	printBinaryArray(exiIn->V2G_Message.Header.SessionID.bytes, exiIn->V2G_Message.Header.SessionID.bytesLen);
	printf("\t\t EVCCID=%d\n", exiIn->V2G_Message.Body.SessionSetupReq.EVCCID.bytes[0]);

	exiOut->V2G_Message_isUsed = 1u;

	/* generate an unique sessionID */
	init_iso1MessageHeaderType(&exiOut->V2G_Message.Header);
	exiOut->V2G_Message.Header.SessionID.bytes[0] = 1;
	exiOut->V2G_Message.Header.SessionID.bytes[1] = 2;
	exiOut->V2G_Message.Header.SessionID.bytes[2] = 3;
	exiOut->V2G_Message.Header.SessionID.bytes[3] = 4;
	exiOut->V2G_Message.Header.SessionID.bytes[4] = 5;
	exiOut->V2G_Message.Header.SessionID.bytes[5] = 6;
	exiOut->V2G_Message.Header.SessionID.bytes[6] = 7;
	exiOut->V2G_Message.Header.SessionID.bytes[7] = 8;
	exiOut->V2G_Message.Header.SessionID.bytesLen = 8;
	
	init_iso1BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.SessionSetupRes_isUsed = 1u;
	init_iso1SessionSetupResType(&exiOut->V2G_Message.Body.SessionSetupRes);

	exiOut->V2G_Message.Body.SessionSetupRes.ResponseCode = iso1responseCodeType_OK;
	exiOut->V2G_Message.Body.SessionSetupRes.EVSEID.characters[0] = 0;
	exiOut->V2G_Message.Body.SessionSetupRes.EVSEID.characters[1] = 20;
	exiOut->V2G_Message.Body.SessionSetupRes.EVSEID.charactersLen = 2;
	exiOut->V2G_Message.Body.SessionSetupRes.EVSETimeStamp_isUsed = 1u;
	exiOut->V2G_Message.Body.SessionSetupRes.EVSETimeStamp = 123456789;

	return 0;
}



static int serviceDetail1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut) {

	printf("EVSE side: serviceDetail called\n"  );
	printf("\tReceived data:\n");
	printf("\tHeader SessionID=");
	printBinaryArray(exiIn->V2G_Message.Header.SessionID.bytes, exiIn->V2G_Message.Header.SessionID.bytesLen);
	printf("\t\t ServiceDetailID=%d\n",exiIn->V2G_Message.Body.ServiceDetailReq.ServiceID);


	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso1BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.ServiceDetailRes_isUsed= 1u;
	init_iso1ServiceDetailResType(&exiOut->V2G_Message.Body.ServiceDetailRes);

	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceID = 1234;

	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList_isUsed = 1u;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.arrayLen = 2;

	/* Parameter Set 1*/
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].ParameterSetID = 1;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.arrayLen = 2;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.charactersLen = 8;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[0] = 'P';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[1] = 'r';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[2] = 'o';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[3] = 't';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[4]= 'o';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[5] = 'c';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[6] = 'o';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].Name.characters[7] = 'l';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].intValue = 15119;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[0].intValue_isUsed = 1u;

	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].Name.charactersLen = 4;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].Name.characters[0] = 'N';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].Name.characters[1] = 'a';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].Name.characters[2] = 'm';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].Name.characters[3] = 'e';

	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].stringValue_isUsed = 1u;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].stringValue.charactersLen = 3;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].stringValue.characters[0] = 'V';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].stringValue.characters[1] = '2';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[0].Parameter.array[1].stringValue.characters[2] = 'G';

	/* Parameter Set 2 */
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].ParameterSetID = 2;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.arrayLen = 1;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.charactersLen = 7;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[0] = 'C';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[1] = 'h';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[2] = 'a';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[3] = 'n';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[4] = 'n';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[5] = 'e';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].Name.characters[6] = 'l';
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].physicalValue_isUsed = 1u;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].physicalValue.Value = 1234;

	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].physicalValue.Multiplier = 1;
	exiOut->V2G_Message.Body.ServiceDetailRes.ServiceParameterList.ParameterSet.array[1].Parameter.array[0].physicalValue.Value = 2;

	exiOut->V2G_Message.Body.ServiceDetailRes.ResponseCode = iso1responseCodeType_OK;

	return 0;
}



static int authorization1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut) {

	printf("EVSE: Authorization called\n"  );
	printf("\tReceived data:\n");

	if(exiIn->V2G_Message.Body.AuthorizationReq.GenChallenge_isUsed) {
		printf("\t\t\t GenChallenge=%d\n", exiIn->V2G_Message.Body.AuthorizationReq.GenChallenge.bytes[0]);
	}
	if(exiIn->V2G_Message.Body.AuthorizationReq.Id_isUsed ) {
		printf("\t\t\t ID=%c%c%c\n", exiIn->V2G_Message.Body.AuthorizationReq.Id.characters[0], exiIn->V2G_Message.Body.AuthorizationReq.Id.characters[1], exiIn->V2G_Message.Body.AuthorizationReq.Id.characters[2]);
	}


	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso1BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.AuthorizationRes_isUsed = 1u;
	init_iso1AuthorizationResType(&exiOut->V2G_Message.Body.AuthorizationRes);

	exiOut->V2G_Message.Body.AuthorizationRes.ResponseCode = iso1responseCodeType_OK;
	exiOut->V2G_Message.Body.AuthorizationRes.EVSEProcessing = iso1EVSEProcessingType_Finished;

	return 0;
}


static int powerDelivery1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut) {
	printf("EVSE side: powerDelivery called\n"  );
	printf("\tReceived data:\n");

	printf("\t\t  ChargeProgress=%d\n", exiIn->V2G_Message.Body.PowerDeliveryReq.ChargeProgress);
	printf("\t\t  SAScheduleTupleID=%d\n", exiIn->V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID);

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso1BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.PowerDeliveryRes_isUsed = 1u;
	init_iso1PowerDeliveryResType(&exiOut->V2G_Message.Body.PowerDeliveryRes);

	exiOut->V2G_Message.Body.PowerDeliveryRes.ResponseCode = iso1responseCodeType_OK;

	exiOut->V2G_Message.Body.PowerDeliveryRes.EVSEStatus_isUsed = 1;
	exiOut->V2G_Message.Body.PowerDeliveryRes.EVSEStatus.EVSENotification = iso1EVSENotificationType_StopCharging;
	exiOut->V2G_Message.Body.PowerDeliveryRes.EVSEStatus.NotificationMaxDelay=12;

	return 0;
}


static int chargingStatus1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut) {

	printf("EVSE side: chargingStatus called\n"  );

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso1BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.ChargingStatusRes_isUsed = 1u;
	init_iso1ChargingStatusResType(&exiOut->V2G_Message.Body.ChargingStatusRes);


	exiOut->V2G_Message.Body.ChargingStatusRes.ResponseCode = iso1responseCodeType_OK;
	exiOut->V2G_Message.Body.ChargingStatusRes.EVSEID.characters[0]= 'A';
	exiOut->V2G_Message.Body.ChargingStatusRes.EVSEID.charactersLen =1;

	exiOut->V2G_Message.Body.ChargingStatusRes.ReceiptRequired = 1;
	exiOut->V2G_Message.Body.ChargingStatusRes.ReceiptRequired_isUsed = 1;

	return 0;
}


static int meteringReceipt1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut) {

	printf("EVSE side: meteringReceipt called\n"  );
	printf("\tReceived data:\n");

	printf("\t\t ID=%c%c%c\n", exiIn->V2G_Message.Body.MeteringReceiptReq.Id.characters[0], exiIn->V2G_Message.Body.MeteringReceiptReq.Id.characters[1], exiIn->V2G_Message.Body.MeteringReceiptReq.Id.characters[2]);
	printf("\t\t SAScheduleTupleID=%d\n", exiIn->V2G_Message.Body.MeteringReceiptReq.SAScheduleTupleID);
	printf("\t\t SessionID=%d\n", exiIn->V2G_Message.Body.MeteringReceiptReq.SessionID.bytes[1]);
	printf("\t\t MeterInfo.MeterStatus=%d\n", exiIn->V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterStatus);
	printf("\t\t MeterInfo.MeterID=%d\n",		exiIn->V2G_Message.Body.MeteringReceiptReq.MeterInfo.MeterID.characters[0]);

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso1BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.MeteringReceiptRes_isUsed = 1u;
	init_iso1MeteringReceiptResType(&exiOut->V2G_Message.Body.MeteringReceiptRes);

	exiOut->V2G_Message.Body.MeteringReceiptRes.ResponseCode = iso1responseCodeType_FAILED;

	return 0;
}

static int sessionStop1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut) {

	printf("EVSE side: sessionStop called\n"  );
	printf("\tReceived data:\n");
	printf("\tHeader SessionID=");
	printBinaryArray(exiIn->V2G_Message.Header.SessionID.bytes, exiIn->V2G_Message.Header.SessionID.bytesLen);
	printf("\t\t ChargingSession=%d\n", exiIn->V2G_Message.Body.SessionStopReq.ChargingSession);

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso1BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.SessionStopRes_isUsed = 1u;
	init_iso1SessionStopResType(&exiOut->V2G_Message.Body.SessionStopRes);

	exiOut->V2G_Message.Body.SessionStopRes.ResponseCode = iso1responseCodeType_OK;

	return 0;
}

static int cableCheck1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut) {

	printf("EVSE side: cableCheck called\n"  );

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso1BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.CableCheckRes_isUsed = 1u;
	init_iso1CableCheckResType(&exiOut->V2G_Message.Body.CableCheckRes);

	exiOut->V2G_Message.Body.CableCheckRes.ResponseCode = iso1responseCodeType_OK;

	exiOut->V2G_Message.Body.CableCheckRes.DC_EVSEStatus.NotificationMaxDelay = 1234;
	exiOut->V2G_Message.Body.CableCheckRes.DC_EVSEStatus.EVSENotification= iso1EVSENotificationType_ReNegotiation;

	exiOut->V2G_Message.Body.CableCheckRes.EVSEProcessing = iso1EVSEProcessingType_Finished;

	return 0;
}

static int preCharge1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut) {

	printf("EVSE side: preCharge called\n"  );
	printf("\tReceived data:\n");

	printf("\t\t EVTargetCurrent=%d (%d)\n", exiIn->V2G_Message.Body.PreChargeReq.EVTargetCurrent.Value, exiIn->V2G_Message.Body.PreChargeReq.EVTargetCurrent.Multiplier);
	printf("\t\t EVTargetVoltage=%d (%d)\n", exiIn->V2G_Message.Body.PreChargeReq.EVTargetVoltage.Value, exiIn->V2G_Message.Body.PreChargeReq.EVTargetVoltage.Multiplier);

	/* Prepare data for EV */
	exiOut->V2G_Message_isUsed = 1u;
	init_iso1BodyType(&exiOut->V2G_Message.Body);

	exiOut->V2G_Message.Body.PreChargeRes_isUsed = 1u;
	init_iso1PreChargeResType(&exiOut->V2G_Message.Body.PreChargeRes);

	exiOut->V2G_Message.Body.PreChargeRes.ResponseCode = iso1responseCodeType_OK;

	exiOut->V2G_Message.Body.PreChargeRes.DC_EVSEStatus.EVSENotification = iso1EVSENotificationType_StopCharging;
	exiOut->V2G_Message.Body.PreChargeRes.DC_EVSEStatus.NotificationMaxDelay= 1234;

	exiOut->V2G_Message.Body.PreChargeRes.EVSEPresentVoltage.Multiplier = 3;
	exiOut->V2G_Message.Body.PreChargeRes.EVSEPresentVoltage.Value= 456;

	return 0;
}




/**
 * @brief Creates a response message based on the received request.
 *
 * This function creates a response message as an ISO1 EXI document (`exiOut`) based on
 * the received request message (`exiIn`). It checks the type of request message and calls the
 * corresponding function to generate the response.
 *
 * @param exiIn Pointer to the received ISO1 EXI document representing the request.
 * @param exiOut Pointer to the ISO1 EXI document where the response will be stored.
 * @return Returns 0 on success, or an error code indicating the failure.
 */
static int create_response_message1(struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut) {
	int errn = ERROR_UNEXPECTED_REQUEST_MESSAGE;

	/* create response message as EXI document */
	if(exiIn->V2G_Message_isUsed) {
		init_iso1EXIDocument(exiOut);
		if (exiIn->V2G_Message.Body.SessionSetupReq_isUsed) {
			errn = sessionSetup1(exiIn, exiOut);
		} 
		else if (exiIn->V2G_Message.Body.ServiceDetailReq_isUsed) {
			errn = serviceDetail1(exiIn, exiOut);
		} 
		// else if (exiIn->V2G_Message.Body.PaymentDetailsReq_isUsed) {
		// 	errn = paymentDetails1(exiIn, exiOut);
		// } 
		else if (exiIn->V2G_Message.Body.AuthorizationReq_isUsed) {
			errn = authorization1(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.PowerDeliveryReq_isUsed) {
			errn = powerDelivery1(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.ChargingStatusReq_isUsed) {
			errn = chargingStatus1(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.MeteringReceiptReq_isUsed) {
			errn = meteringReceipt1(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.SessionStopReq_isUsed) {
			errn = sessionStop1(exiIn, exiOut);
			finished = 1;
		} else if (exiIn->V2G_Message.Body.CableCheckReq_isUsed) {
			errn = cableCheck1(exiIn, exiOut);
		} else if (exiIn->V2G_Message.Body.PreChargeReq_isUsed) {
			errn = preCharge1(exiIn, exiOut);
		}
	}

	return errn;
}


/**
 * @brief Performs the request-response interaction for charging between the EV and the EVSE.
 *
 * This function handles the request-response interaction for the charging process between
 * the Electric Vehicle (EV) and the Electric Vehicle Supply Equipment (EVSE). It deserializes
 * the request message from `stream1`, creates a response message, serializes the response,
 * and writes it to `stream2`.
 *
 * @param stream1 Pointer to the bitstream containing the request from the EVSE.
 * @param stream2 Pointer to the bitstream where the response to the EVSE will be written.
 * @param exiIn Pointer to the EXI document structure for input.
 * @param exiOut Pointer to the EXI document structure for output.
 * @return Returns 0 on success, or an error code indicating the failure.
 */
static int request_response1(bitstream_t* stream1, bitstream_t* stream2 , struct iso1EXIDocument* exiIn, struct iso1EXIDocument* exiOut) {
	int errn;

	size_t pos2;

	stream2->size = BUFFER_SIZE;
	stream2->data = buffer2;
	stream2->pos = &pos2;


	/* deserialize request message */
	if (errn == 0) {
		errn = deserialize1Stream2EXI(stream1, exiOut);
	}
	/* create response message */
	if (errn == 0) {
		errn = create_response_message1(exiOut, exiIn);
	}
	/* serialize response message */
	if (errn == 0) {
		errn = serialize1EXI2Stream(exiIn, stream2);
	}
	/* <-- End of EVSE side */
	return errn;
}

/**
 * @brief Handles the charging1 process on the EV side.
 *
 * This function handles the charging process on the Electric Vehicle (EV) side.
 * It invokes the `request_response1` function to perform the charging request-response
 * interaction between the EV and the EVSE (Electric Vehicle Supply Equipment).
 *
 * @param stream1 Pointer to the bitstream containing the request from the EVSE.
 * @param stream2 Pointer to the bitstream where the response to the EVSE will be written.
 * @return Returns 0 on success, or an error code indicating the failure.
 */
static int charging1(bitstream_t* stream1, bitstream_t* stream2) 
{
	int errn = 0;
	int i, j;


	errn = request_response1(stream1, stream2, &exiIn1, &exiOut1);
			
	return errn;
	
}
#endif /* DEPLOY_ISO1_CODEC == SUPPORT_YES */



// Main server function
/**
 * @function server_tls
 * @brief Initializes a server with TLS using wolfSSL and handles client connections.
 *
 * This function sets up a TLS server using the wolfSSL library. It initializes the SSL/TLS context,
 * configures the server address, binds the server socket to the specified port, and then accepts and
 * handles client connections. Upon completion or if an error occurs, the function performs necessary
 * cleanup.
 *
 * @param CERT_FILE The file path to the server's TLS certificate in PEM format.
 * @param KEY_FILE The file path to the server's TLS private key in PEM format.
 * @param DEFAULT_PORT The port number the server will listen on.
 *
 * @return void This function does not return a value, but it uses a return code to handle errors internally.
 *
 * @note The function utilizes helper functions `initialize_wolfssl`, `configure_server_address`, `bind_server_socket`,
 * `accept_and_handle_client_connections`, and `cleanup_and_exit` for specific tasks.
 *
 * @note If an error occurs during the initialization, configuration, or binding, the function will exit early
 * and clean up resources to prevent resource leaks.
 */
void server_tls(const char *CERT_FILE, const char *KEY_FILE, int DEFAULT_PORT) {
    int ret = 0;
    int sockfd = -1;      // Server socket file descriptor
    WOLFSSL_CTX *ctx = NULL;  // SSL/TLS context object

    // Initialize wolfSSL and server socket
    ret = initialize_wolfssl(CERT_FILE, KEY_FILE, &sockfd, &ctx);
    if (ret == -1) {
        goto exit;
    }

    // Server address configuration
    struct sockaddr_in servAddr;
    configure_server_address(&servAddr, DEFAULT_PORT);

    // Bind the server socket
    ret = bind_server_socket(sockfd, &servAddr);
    if (ret == -1) {
        goto exit;
    }

    // Accept and handle client connections
    accept_and_handle_client_connections(sockfd, ctx);

exit:
    // Clean up resources
    cleanup_and_exit(NULL, -1, sockfd, ctx);
}

// Function definitions

// Initializes wolfSSL and the server socket
/**
 * @function initialize_wolfssl
 * @brief Initializes wolfSSL and the server socket.
 *
 * This function initializes the wolfSSL library and sets up a server socket with the provided SSL/TLS
 * context. It creates and configures the server socket and initializes a wolfSSL context with the
 * specified TLS version. It also loads the server's certificate and private key into the context.
 * The function handles any errors that arise during initialization and returns an appropriate status code.
 *
 * @param CERT_FILE The file path to the server's TLS certificate in PEM format.
 * @param KEY_FILE The file path to the server's TLS private key in PEM format.
 * @param sockfd A pointer to an integer to hold the server socket file descriptor.
 * @param ctx A pointer to a WOLFSSL_CTX pointer that will be initialized with the SSL/TLS context object.
 *
 * @return int Returns 0 on success, or -1 on failure.
 */
int initialize_wolfssl(const char *CERT_FILE, const char *KEY_FILE, int *sockfd, WOLFSSL_CTX **ctx) {
    // Initialize wolfSSL
    wolfSSL_Init();

    // Create server socket
    *sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (*sockfd == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        return -1;
    }

    // Create and initialize WOLFSSL_CTX
    *ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    if (*ctx == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        return -1;
    }

    // Load server certificates into WOLFSSL_CTX
    if (wolfSSL_CTX_use_certificate_file(*ctx, CERT_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n", CERT_FILE);
        return -1;
    }

    // Load server key into WOLFSSL_CTX
    if (wolfSSL_CTX_use_PrivateKey_file(*ctx, KEY_FILE, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n", KEY_FILE);
        return -1;
    }

    return 0;
}

// Configures server address and port
/**
 * @function configure_server_address
 * @brief Configures the server address structure for the given port.
 *
 * This function initializes the server address structure to set up a server socket.
 * It sets the address family to IPv4 (`AF_INET`), the port number to the provided
 * `DEFAULT_PORT` and the IP address to `INADDR_ANY`
 * to allow the server to accept connections from any interface.
 *
 * @param servAddr A pointer to a `struct sockaddr_in` structure that will be initialized.
 * @param DEFAULT_PORT The port number the server will listen on.
 *
 * @return void This function does not return a value.
 */
void configure_server_address(struct sockaddr_in *servAddr, int DEFAULT_PORT) {
    // Initialize the server address structure
    memset(servAddr, 0, sizeof(*servAddr));
    servAddr->sin_family = AF_INET;  // Use IPv4
    servAddr->sin_port = htons(DEFAULT_PORT);
    servAddr->sin_addr.s_addr = INADDR_ANY;
}

// Binds the server socket to the server address
/**
 * @function bind_server_socket
 * @brief Binds the server socket to the specified server address and sets it to listen for connections.
 *
 * This function binds the server socket (`sockfd`) to the server address specified by `servAddr`.
 * If the binding operation fails, an error message is printed and the function returns a status code
 * of `-1`. If the binding is successful, the function then sets the server socket to listen for incoming
 * connections with a backlog of up to 5 connections. If the listen operation fails, an error message
 * is printed and the function returns a status code of `-1`.
 *
 * @param sockfd The server socket file descriptor that will be bound to the server address.
 * @param servAddr A pointer to a `struct sockaddr_in` structure specifying the server address to bind the socket to.
 *
 * @return int Returns 0 on success (both binding and listening are successful), or -1 on failure.
 */
int bind_server_socket(int sockfd, struct sockaddr_in *servAddr) {
    if (bind(sockfd, (struct sockaddr *)servAddr, sizeof(*servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to bind\n");
        return -1;
    }

    // Listen for connections
    if (listen(sockfd, 5) == -1) {
        fprintf(stderr, "ERROR: failed to listen\n");
        return -1;
    }

    return 0;
}

// Accepts and handles client connections
/**
 * @function accept_and_handle_client_connections
 * @brief Accepts and handles client connections using the specified server socket and SSL/TLS context.
 *
 * This function continuously waits for client connections on the server socket (`sockfd`).
 * Upon accepting a connection, it creates a new `WOLFSSL` object from the provided `ctx` context,
 * attaches the SSL object to the accepted connection, and then delegates handling the client connection
 * to the `handle_client_connection` function. Once the client connection has been handled or if any errors
 * occur, the function closes the connection and frees the SSL object.
 *
 * @param sockfd The server socket file descriptor on which the server listens for client connections.
 * @param ctx The SSL/TLS context object (`WOLFSSL_CTX`) to be used for creating new SSL objects.
 *
 * @return void This function does not return a value as it runs an infinite loop to continuously accept and handle client connections.
 *
 * @note Errors encountered during the process of accepting or handling a client connection are handled by printing
 * an error message and continuing to the next iteration to accept new connections.
 */
void accept_and_handle_client_connections(int sockfd, WOLFSSL_CTX *ctx) {
    struct sockaddr_in clientAddr;
    socklen_t size = sizeof(clientAddr);

    while (1) {
        printf("Waiting for a connection...\n");

        // Accept client connections
        int connd = accept(sockfd, (struct sockaddr *)&clientAddr, &size);
        if (connd == -1) {
            fprintf(stderr, "ERROR: failed to accept the connection\n");
            continue;
        }

        // Handle client connection
        WOLFSSL *ssl = wolfSSL_new(ctx);
        if (!ssl) {
            fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
            close(connd);
            continue;
        }

        // Attach wolfSSL to the client connection
        wolfSSL_set_fd(ssl, connd);

        // Handle client connection
        if (handle_client_connection(ssl, connd) == -1) {
            close(connd);
            wolfSSL_free(ssl);
            continue;
        }

        // Close the client connection
        close(connd);
        wolfSSL_free(ssl);
    }
}

// Handles client connection
/**
 * @function handle_client_connection
 * @brief Handles communication with a connected client using the specified SSL connection.
 *
 * This function establishes a TLS connection with a connected client using the provided `ssl`
 * object. It enters a loop to continuously read data from the client, process the received data,
 * and send a response back to the client. The function uses bitstreams (`stream1` and `stream2`)
 * to handle data processing and response preparation. The loop continues until a termination condition
 * is met or an error occurs. Upon completion, the function gracefully shuts down the SSL connection.
 *
 * @param ssl A `WOLFSSL` object representing the SSL/TLS connection to the client.
 * @param connd The file descriptor for the client's connection socket.
 *
 * @return int Returns 0 on success or -1 on failure.
 *
 * @note If an error occurs during SSL/TLS connection establishment or data handling, the function
 * prints an error message and returns a status code of `-1`.
 *
 * @note The function uses helper functions such as `write_response`, `appHandshake` and `charging2`
 * to handle client communication and data processing.
 *
 * @note Ensure that `buff`, `BUFFER_SIZE`, `countcase`, `finished`, and the data processing functions
 * (`appHandshake` and `charging2`) are properly defined and implemented in your program.
 */
int handle_client_connection(WOLFSSL *ssl, int connd) {
    // Establish the TLS connection
    int ret = wolfSSL_accept(ssl);
    if (ret != WOLFSSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_accept error = %d\n", wolfSSL_get_error(ssl, ret));
        return -1;
    }

    printf("Client connected successfully\n");
    const WOLFSSL_CIPHER *cipher = wolfSSL_get_current_cipher(ssl);
    printf("SSL cipher suite is %s\n", wolfSSL_CIPHER_get_name(cipher));

    // Handle client communication
    bitstream_t stream1, stream2;


    while (1) {
        // Read data from the client
        memset(buff, 0, sizeof(buff));
        ret = wolfSSL_read(ssl, buff, 255);
        if (ret == -1) {
            fprintf(stderr, "ERROR: failed to read\n");
            return -1;
        }

        // Process received data
        stream1.size = BUFFER_SIZE;
        stream1.data = buff;

        if (finished == 1) {
            countcase = 0;
            finished = 0;
            break;
        } else if (buff[0] == 0) {
            continue;
        } else if (countcase == 0) {
            appHandshake(&stream1, &stream2);
        } else if (countcase == 1) {
            charging2(&stream1, &stream2);
        }

        // Respond to the client using write_response function
        ret = write_response(ssl, &stream2);
        if (ret == -1) {
            return -1;
        }
    }

    // Close the SSL connection
    wolfSSL_shutdown(ssl);
    printf("Shutdown complete\n");

    return 0;
}

// Cleans up resources and exits
/**
 * @function cleanup_and_exit
 * @brief Cleans up resources and exits the program.
 *
 * This function frees and cleans up resources such as the `ssl` object, connection socket (`connd`),
 * server socket (`sockfd`), and SSL/TLS context (`ctx`). It also performs any final cleanup required
 * by the wolfSSL library using `wolfSSL_Cleanup()`. This function should be called before exiting the program
 * to avoid resource leaks.
 *
 * @param ssl A `WOLFSSL` object representing the SSL/TLS connection to the client. It is freed if non-NULL.
 * @param connd The file descriptor for the client's connection socket. The function closes it if it's not equal to `-1`.
 * @param sockfd The server socket file descriptor. The function closes it if it's not equal to `-1`.
 * @param ctx The SSL/TLS context object (`WOLFSSL_CTX`). It is freed if non-NULL.
 *
 * @return void This function does not return a value.
 */
void cleanup_and_exit(WOLFSSL *ssl, int connd, int sockfd, WOLFSSL_CTX *ctx) {
    if (ssl) {
        wolfSSL_free(ssl);
    }
    if (connd != -1) {
        close(connd);
    }
    if (sockfd != -1) {
        close(sockfd);
    }
    if (ctx) {
        wolfSSL_CTX_free(ctx);
    }
    wolfSSL_Cleanup();
}