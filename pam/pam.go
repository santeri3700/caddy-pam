package pam

// #include "pam.h"
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

func init() {
	C.initialize()
}

var results = map[int]string{
	int(C.PAM_OPEN_ERR):              "PAM_OPEN_ERR",
	int(C.PAM_SYMBOL_ERR):            "PAM_SYMBOL_ERR",
	int(C.PAM_SERVICE_ERR):           "PAM_SERVICE_ERR",
	int(C.PAM_SYSTEM_ERR):            "PAM_SYSTEM_ERR",
	int(C.PAM_BUF_ERR):               "PAM_BUF_ERR",
	int(C.PAM_PERM_DENIED):           "PAM_PERM_DENIED",
	int(C.PAM_AUTH_ERR):              "PAM_AUTH_ERR",
	int(C.PAM_CRED_INSUFFICIENT):     "PAM_CRED_INSUFFICIENT",
	int(C.PAM_AUTHINFO_UNAVAIL):      "PAM_AUTHINFO_UNAVAIL",
	int(C.PAM_USER_UNKNOWN):          "PAM_USER_UNKNOWN",
	int(C.PAM_MAXTRIES):              "PAM_MAXTRIES",
	int(C.PAM_NEW_AUTHTOK_REQD):      "PAM_NEW_AUTHTOK_REQD",
	int(C.PAM_ACCT_EXPIRED):          "PAM_ACCT_EXPIRED",
	int(C.PAM_SESSION_ERR):           "PAM_SESSION_ERR",
	int(C.PAM_CRED_UNAVAIL):          "PAM_CRED_UNAVAIL",
	int(C.PAM_CRED_EXPIRED):          "PAM_CRED_EXPIRED",
	int(C.PAM_CRED_ERR):              "PAM_CRED_ERR",
	int(C.PAM_NO_MODULE_DATA):        "PAM_NO_MODULE_DATA",
	int(C.PAM_CONV_ERR):              "PAM_CONV_ERR",
	int(C.PAM_AUTHTOK_ERR):           "PAM_AUTHTOK_ERR",
	int(C.PAM_AUTHTOK_RECOVERY_ERR):  "PAM_AUTHTOK_RECOVERY_ERR",
	int(C.PAM_AUTHTOK_LOCK_BUSY):     "PAM_AUTHTOK_LOCK_BUSY",
	int(C.PAM_AUTHTOK_DISABLE_AGING): "PAM_AUTHTOK_DISABLE_AGING",
	int(C.PAM_TRY_AGAIN):             "PAM_TRY_AGAIN",
	int(C.PAM_IGNORE):                "PAM_IGNORE",
	int(C.PAM_ABORT):                 "PAM_ABORT",
	int(C.PAM_AUTHTOK_EXPIRED):       "PAM_AUTHTOK_EXPIRED",
	int(C.PAM_MODULE_UNKNOWN):        "PAM_MODULE_UNKNOWN",
	int(C.PAM_BAD_ITEM):              "PAM_BAD_ITEM",
	int(C.PAM_CONV_AGAIN):            "PAM_CONV_AGAIN",
}

// Result returns the symbolic name of a PAM return code.
func Result(code int) string {
	if name, ok := results[code]; ok {
		return name
	}
	return fmt.Sprintf("PAM_UNKNOWN_ERR_%d", code)
}

func Authenticate(username string, password string) (bool, error) {

	user := C.CString(username)
	defer C.free(unsafe.Pointer(user))

	pass := C.CString(password)
	defer C.free(unsafe.Pointer(pass))

	var errcode C.int = 0

	var ok = C.authenticate_system(user, pass, &errcode)

	if ok != 1 {
		return false, errors.New(Result(int(errcode)))
	} else {
		return true, nil
	}

}
