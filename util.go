package zkmgr

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"unicode/utf8"
)

// zkAuthACL produces an zkACL list containing a single zkACL which uses the
// provided permissions, with the scheme "auth", and ID "", which is used
// by ZooKeeper to represent any authenticated user.
func zkAuthACL(perms int32) []zkACL {
	return []zkACL{{perms, "auth", ""}}
}

// zkWorldACL produces an zkACL list containing a single zkACL which uses the
// provided permissions, with the scheme "world", and ID "anyone", which
// is used by ZooKeeper to represent any user at all.
func zkWorldACL(perms int32) []zkACL {
	return []zkACL{{perms, "world", "anyone"}}
}

func DigestACL(perms int32, user, password string) []zkACL {
	userPass := []byte(fmt.Sprintf("%s:%s", user, password))
	h := sha1.New()
	if n, err := h.Write(userPass); err != nil || n != len(userPass) {
		panic("SHA1 failed")
	}
	digest := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return []zkACL{{perms, "digest", fmt.Sprintf("%s:%s", user, digest)}}
}

// FormatServers takes a slice of addresses, and makes sure they are in a format
// that resembles <addr>:<port>. If the server has no port provided, the
// DefaultPort constant is added to the end.
func FormatServers(servers []string) []string {
	srvs := make([]string, len(servers))
	for i, addr := range servers {
		if strings.Contains(addr, ":") {
			srvs[i] = addr
		} else {
			srvs[i] = addr + ":" + strconv.Itoa(DefaultPort)
		}
	}
	return srvs
}

// stringShuffle performs a Fisher-Yates shuffle on a slice of strings
func stringShuffle(s []string) {
	for i := len(s) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		s[i], s[j] = s[j], s[i]
	}
}

// validatePath will make sure a path is valid before sending the request
func validatePath(path string, isSequential bool) error {
	if path == "" {
		log.Printf("[E]path is empty\n")
		return zkErrInvalidPath
	}

	if path[0] != '/' {
		log.Printf("[E]path(%s) is not begin with / charater\n", path)
		return zkErrInvalidPath
	}

	n := len(path)
	if n == 1 {
		// path is just the root
		return nil
	}

	if !isSequential && path[n-1] == '/' {
		log.Printf("[E]not Sequential path(%s) must end with / charater\n", path)
		return zkErrInvalidPath
	}

	// Start at rune 1 since we already know that the first character is
	// a '/'.
	for i, w := 1, 0; i < n; i += w {
		r, width := utf8.DecodeRuneInString(path[i:])
		switch {
		case r == '\u0000':
			return zkErrInvalidPath
		case r == '/':
			last, _ := utf8.DecodeLastRuneInString(path[:i])
			if last == '/' {
				return zkErrInvalidPath
			}
		case r == '.':
			last, lastWidth := utf8.DecodeLastRuneInString(path[:i])

			// Check for double dot
			if last == '.' {
				last, _ = utf8.DecodeLastRuneInString(path[:i-lastWidth])
			}

			if last == '/' {
				if i+1 == n {
					return zkErrInvalidPath
				}

				next, _ := utf8.DecodeRuneInString(path[i+w:])
				if next == '/' {
					return zkErrInvalidPath
				}
			}
		case r >= '\u0000' && r <= '\u001f',
			r >= '\u007f' && r <= '\u009f',
			r >= '\uf000' && r <= '\uf8ff',
			r >= '\ufff0' && r < '\uffff':
			return zkErrInvalidPath
		}
		w = width
	}
	return nil
}
