package zkmgr

import (
	"fmt"
	"log"
)

// wrapLogger wraps a Go kit logger so we can use it as the logging service for
// the ZooKeeper library, which expects a Printf method to be available.
type wrapLogger struct {
}

func (logger wrapLogger) Printf(format string, args ...interface{}) {
	log.Printf("[I]msg(%s)\n", fmt.Sprintf(format, args...))
}

// withLogger replaces the ZooKeeper library's default logging service with our
// own Go kit logger.
func withLogger() func(c *zkConn) {
	return func(c *zkConn) {
		c.SetLogger(wrapLogger{})
	}
}
