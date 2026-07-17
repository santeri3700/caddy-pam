#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include "pam_types.h"

// https://www.scs.stanford.edu/~dm/blog/va-opt.html
#define PARENS ()

#define EXPAND(...) EXPAND4(EXPAND4(EXPAND4(EXPAND4(__VA_ARGS__))))
#define EXPAND4(...) EXPAND3(EXPAND3(EXPAND3(EXPAND3(__VA_ARGS__))))
#define EXPAND3(...) EXPAND2(EXPAND2(EXPAND2(EXPAND2(__VA_ARGS__))))
#define EXPAND2(...) EXPAND1(EXPAND1(EXPAND1(EXPAND1(__VA_ARGS__))))
#define EXPAND1(...) __VA_ARGS__

#define FOR_EACH(macro, ...) __VA_OPT__(EXPAND(FOR_EACH_HELPER(macro, __VA_ARGS__)))
#define FOR_EACH_HELPER(macro, a1, a2, ...) macro(a1, a2) __VA_OPT__(, FOR_EACH_AGAIN PARENS (macro, __VA_ARGS__))
#define FOR_EACH_AGAIN() FOR_EACH_HELPER

#define EXTRACT_SECOND(x, y) y
#define EXTRACT_FIRST(x, y) x
#define JOINER(x, y) x y

#define EXTRACT_EACH_SECOND(...) FOR_EACH(EXTRACT_SECOND, __VA_ARGS__)
#define EXTRACT_EACH_FIRST(...) FOR_EACH(EXTRACT_FIRST, __VA_ARGS__)
#define EXTRACT_EACH_ARG(...) FOR_EACH(JOINER, __VA_ARGS__)

#define WRAPPER(rettype, name, ...) static inline rettype name(EXTRACT_EACH_ARG(__VA_ARGS__)) { \
	return ((rettype(*)(EXTRACT_EACH_FIRST(__VA_ARGS__)))dlsym(libpam, #name))(EXTRACT_EACH_SECOND(__VA_ARGS__)); \
}

static void* libpam = 0;

WRAPPER(int, pam_start,const char*, service_name, const char *,user, const struct pam_conv *, pam_conversation, pam_handle_t **, pamh)
WRAPPER(int, pam_authenticate,pam_handle_t *,pamh, int, flags)
WRAPPER(int, pam_end,pam_handle_t *,pamh, int, pam_status)
WRAPPER(int, pam_acct_mgmt,pam_handle_t *,pamh, int, flags)

static inline void initialize() {
	(void)(
		(libpam = dlopen("libpam.so.0", RTLD_LAZY))
	);
}

static inline int function_conversation(int num_msg, const struct pam_message** msg, struct pam_response** resp, void* appdata_ptr) {
	*resp = (struct pam_response*)appdata_ptr;
	return PAM_SUCCESS;
}

#define TRY(call) do { if((*retval = call) != PAM_SUCCESS) return 0; } while(0)

// this is pretty cursed
static inline int authenticate_system(const char* username, const char* password, int* retval)
{
	struct pam_response* reply = (struct pam_response*) malloc(sizeof(struct pam_response));
	const struct pam_conv local_conversation = { function_conversation, reply };
	pam_handle_t* local_auth_handle = NULL;

	TRY(pam_start("login", username, &local_conversation, &local_auth_handle));

	reply->resp = strdup(password);
	reply->resp_retcode = 0;

	TRY(pam_authenticate(local_auth_handle, 0));
	TRY(pam_acct_mgmt(local_auth_handle, PAM_DISALLOW_NULL_AUTHTOK));
	TRY(pam_end(local_auth_handle, *retval));

	return 1;
}