package pam

// #include "pam.h"
import "C"
import (
	"fmt"
	"unsafe"
)

func init() {
	C.initialize()
}

var results = map[int]string{
	int(C.PAM_OPEN_ERR):              "System open error",
	int(C.PAM_SYMBOL_ERR):            "System symbol error",
	int(C.PAM_SERVICE_ERR):           "System service error",
	int(C.PAM_SYSTEM_ERR):            "System error",
	int(C.PAM_BUF_ERR):               "System buffer error",
	int(C.PAM_CONV_ERR):              "Conversation error",
	int(C.PAM_PERM_DENIED):           "Permission denied",
	int(C.PAM_AUTH_ERR):              "Authentication failure",
	int(C.PAM_CRED_INSUFFICIENT):     "Can not access authentication data due to insufficient credentials",
	int(C.PAM_AUTHINFO_UNAVAIL):      "Authentication information unavailable",
	int(C.PAM_USER_UNKNOWN):          "Unknown user",
	int(C.PAM_MAXTRIES):              "Too many authentication attempts",
	int(C.PAM_NEW_AUTHTOK_REQD):      "The user account is valid but the authentication token is expired",
	int(C.PAM_ACCT_EXPIRED):          "User account has expired",
}

// Result returns the symbolic name of a PAM return code.
func Result(code int) string {
	if name, ok := results[code]; ok {
		return name
	}
	return fmt.Sprintf("PAM error code: %d", code)
}

// Error is returned by Authenticate and carries the raw PAM return code.
type Error struct {
	Code int
}

func (e *Error) Error() string { return Result(e.Code) }

func Authenticate(username string, password string) (bool, error) {

	user := C.CString(username)
	defer C.free(unsafe.Pointer(user))

	pass := C.CString(password)
	defer C.free(unsafe.Pointer(pass))

	var errcode C.int = 0

	var ok = C.authenticate_system(user, pass, &errcode)

	if ok != 1 {
		return false, &Error{Code: int(errcode)}
	} else {
		return true, nil
	}

}
