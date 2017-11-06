package raw

import (
	"syscall"
	"time"
)

func newTimeval(timeout time.Duration) syscall.Timeval {
	return syscall.Timeval{
		Sec:  int64(timeout / time.Second),
		Usec: int32(timeout % time.Second / time.Microsecond),
	}
}
