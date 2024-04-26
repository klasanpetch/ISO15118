#include <EVside.h>

#define CA "/home/kla/github/OpenV2G/src/test/ca.crt"
#define PORT_NUMBER  11125

int main_example(int IP_VERSION, char *IP_ADDR[]) {
	int errn = 0;
    clientssl_connect(IP_VERSION , IP_ADDR,CA,PORT_NUMBER);

	
	errn = appHandshake("urn:iso:15118:2:2016:MsgDef");



	
	errn = charging2();

	if(errn != 0) {
		printf("\n\ncharging error %d!\n", errn);
		return errn;
	}

	errn = shutdown_connection();	
}