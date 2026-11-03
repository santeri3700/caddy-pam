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

struct conversation_data {
	const char* username;
	const char* password;
};

static inline void free_responses(struct pam_response* responses, int count) {
	if (responses == NULL) return;
	for (int i = 0; i < count; i++) free(responses[i].resp);
	free(responses);
}

static inline int function_conversation(int num_msg, const struct pam_message** msg, struct pam_response** resp, void* appdata_ptr) {
	if (num_msg <= 0 || num_msg > 64 || msg == NULL || resp == NULL || appdata_ptr == NULL) return PAM_CONV_ERR;
	*resp = NULL;

	const struct conversation_data* credentials = (const struct conversation_data*)appdata_ptr;
	struct pam_response* responses = (struct pam_response*)calloc((size_t)num_msg, sizeof(struct pam_response));
	if (responses == NULL) return PAM_BUF_ERR;

	for (int i = 0; i < num_msg; i++) {
		if (msg[i] == NULL) {
			free_responses(responses, num_msg);
			return PAM_CONV_ERR;
		}

		const char* answer = NULL;
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			answer = credentials->password;
			break;
		case PAM_PROMPT_ECHO_ON:
			answer = credentials->username;
			break;
		case PAM_TEXT_INFO:
		case PAM_ERROR_MSG:
			continue;
		default:
			free_responses(responses, num_msg);
			return PAM_CONV_ERR;
		}

		responses[i].resp = strdup(answer);
		if (responses[i].resp == NULL) {
			free_responses(responses, num_msg);
			return PAM_BUF_ERR;
		}
	}

	*resp = responses;
	return PAM_SUCCESS;
}

static inline int authenticate_system(const char* username, const char* password, int* retval)
{
	const struct conversation_data credentials = { username, password };
	const struct pam_conv local_conversation = { function_conversation, (void*)&credentials };
	pam_handle_t* local_auth_handle = NULL;
	int status = pam_start("login", username, &local_conversation, &local_auth_handle);

	if (status == PAM_SUCCESS && local_auth_handle == NULL) status = PAM_SYSTEM_ERR;
	if (status == PAM_SUCCESS) status = pam_authenticate(local_auth_handle, 0);
	if (status == PAM_SUCCESS) status = pam_acct_mgmt(local_auth_handle, PAM_DISALLOW_NULL_AUTHTOK);
	if (local_auth_handle != NULL) {
		int end_status = pam_end(local_auth_handle, status);
		if (status == PAM_SUCCESS) status = end_status;
	}

	*retval = status;
	return status == PAM_SUCCESS;
}