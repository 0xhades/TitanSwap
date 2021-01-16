// +build !windows

package main

import (
	"fmt"
	"syscall"
)

func maxingFdsLimit() {

	const LimitFds uint64 = 20000

	AssertRLimit := syscall.Rlimit{
		Cur: LimitFds,
		Max: LimitFds,
	}

	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)

	if err != nil {
		fmt.Println("Error Getting Rlimit: ", err)

	}

	rLimit.Max = LimitFds
	rLimit.Cur = LimitFds

	err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		fmt.Println("Error Setting RLimit: ", err)
	}

	err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)

	if err != nil {
		fmt.Println("Error Getting RLimit: ", err)
	}

	if rLimit != AssertRLimit {
		fmt.Println("Error Matching RLimit: ", rLimit)
	}

}

//MessageBoxPlain ..
func MessageBoxPlain(title, caption string) int {
	return 0
}
