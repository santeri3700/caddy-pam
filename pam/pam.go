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

func Authenticate(username string, password string) (bool, error) {

	user := C.CString(username)
	defer C.free(unsafe.Pointer(user))

	pass := C.CString(password)
	defer C.free(unsafe.Pointer(pass))

	var errcode C.int = 0

	var ok = C.authenticate_system(user, pass, &errcode)

	if ok != 1 {
		return false, fmt.Errorf("PAM Error Code %d", int(errcode))
	} else {
		return true, nil
	}

}
