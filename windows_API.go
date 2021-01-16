// +build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	mod = syscall.NewLazyDLL("user32.dll")
	//crtMod = syscall.NewLazyDLL("crtdll.dll")
	messageBoxW = mod.NewProc("MessageBoxW")
	// _setmaxstdio = crtMod.NewProc("_setmaxstdio")
	// _getmaxstdio = crtMod.NewProc("_getmaxstdio")
)

// func setmaxstdio(max int) {
// 	ret, _, _ := _setmaxstdio.Call(uintptr(flags))
// 	return int(ret)
// }

// func getmaxstdio(max int) {
// 	ret, _, _ := _getmaxstdio.Call()
// 	return int(ret)
// }

//MessageBox of Win32 API.
func MessageBox(hwnd uintptr, caption, title string, flags uint) int {
	ret, _, _ := messageBoxW.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(caption))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))),
		uintptr(flags))

	return int(ret)
}

// MessageBoxPlain of Win32 API.
func MessageBoxPlain(title, caption string) int {
	const (
		NULL  = 0
		MB_OK = 0
	)
	return MessageBox(NULL, caption, title, MB_OK)
}

func maxingFdsLimit() {
	return	
}
