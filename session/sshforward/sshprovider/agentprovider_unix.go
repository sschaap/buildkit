// +build !windows

package sshprovider

import (
	"github.com/pkg/errors"
)

func getFallbackAgentPath() (string, error) {
	return "", errors.Errorf("make sure SSH_AUTH_SOCK is set")
}

func getUnixSocketDialer(path string) (*socketDialer, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if fi.Mode()&os.ModeSocket > 0 {
		// Path references a UNIX socket.
		return &socketDialer{path: path, dialer: unixSocketDialer}, nil
	}

	return nil, nil
}

func getWindowsPipeDialer(path string) *socketDialer {
	return nil
}
