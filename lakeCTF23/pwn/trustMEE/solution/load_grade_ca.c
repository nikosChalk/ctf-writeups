/* Force Open-TEE to load the grade_ta.so */

#include "tee_client_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const TEEC_UUID uuid = {
	0x11223344, 0xA710, 0x469E, { 0xAC, 0xC8, 0x5E, 0xDF, 0x8C, 0x85, 0x90, 0xE1 }
};

int main()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Operation operation;
	TEEC_Result tee_rv;
	memset((void *)&operation, 0, sizeof(operation));

	tee_rv = TEEC_InitializeContext(NULL, &context);
	if (tee_rv != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed: 0x%x\n", tee_rv);
		exit(0);
	}

	/*
	Connect to the TA
	*/
	tee_rv = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC,
				  NULL, &operation, NULL);
	if (tee_rv != TEEC_SUCCESS) {
		printf("TEEC_OpenSession failed: 0x%x\n", tee_rv);
		exit(0);
	}
	printf("grade TA reloaded\n");
	return 0;
}
