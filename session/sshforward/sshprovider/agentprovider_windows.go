// +build windows

package sshprovider

import (
	"net"
	"regexp"
	"strings"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

// Returns the Windows OpenSSH agent named pipe path, but
// only if the agent is running. Returns an error otherwise.
func getFallbackAgentPath() (string, error) {
	// Windows OpenSSH agent uses a named pipe rather
	// than a UNIX socket. These pipes do not play nice
	// with os.Stat (which tries to open its target), so
	// use a FindFirstFile syscall to check for existence.
	var fd windows.Win32finddata

	path := `\\.\pipe\openssh-ssh-agent`
	pathPtr, _ := windows.UTF16PtrFromString(path)
	handle, err := windows.FindFirstFile(pathPtr, &fd)

	if err != nil {
		msg := "Windows OpenSSH agent not available at %s." +
			" Enable the SSH agent service or set SSH_AUTH_SOCK."
		return "", errors.Errorf(msg, path)
	}

	_ = windows.CloseHandle(handle)

	return path, nil
}

func getUnixSocketDialer(path string) (*socketDialer, error) {
	if ok, err := isUnixSocketPath(path); err != nil {
		return nil, errors.WithStack(err)
	} else if ok {
		return &socketDialer{path: path, dialer: unixSocketDialer}, nil
	}

	return nil, nil
}

func getWindowsPipeDialer(path string) *socketDialer {
	if isWindowsPipePath(path) {
		return &socketDialer{path: path, dialer: windowsPipeDialer}
	}

	return nil
}

// Returns true if the path references a UNIX socket.
func isUnixSocketPath(path string) (bool, error) {
	// Native UNIX sockets on Windows are represented on the file system by a
	// reparse point with an IO_REPARSE_TAG_AF_UNIX reparse tag. To determine
	// whether a given path references a UNIX socket, we would normally first
	// check if the path is a reparse point using e.g. GetFileAttributes(Ex) or
	// FindFirstFile. However, the relevant FILE_ATTRIBUTE_REPARSE_POINT flag
	// is missing for UNIX sockets on Windows 10 build 1903+. Instead, use
	// CreateFile with OPEN_EXISTING and FILE_FLAG_OPEN_REPARSE POINT to obtain
	// a file handle. Then invoke DeviceIoControl(FSCTL_GET_REPARSE_POINT) to
	// retrieve reparse data. This operation fails if the path is not a reparse
	// point, in which case it is not a UNIX socket. Otherwise, the path is a
	// UNIX socket only if its reparse tag matches IO_REPARSE_TAG_AF_UNIX.
	//
	// See https://github.com/golang/go/issues/33357#issuecomment-520518431

	// Using dwDesiredAccess=GENERIC_READ causes errors
	// if another process acquired an exclusive read lock.
	// Pass dwDesiredAccess=0 and dwShareMode=0 to avoid this.
	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(path),
		0, // Do not request read access
		0, // or share mode to avoid locks
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|
			windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return false, errors.Wrap(err, "unable to open file")
	}

	defer windows.CloseHandle(h)

	var rdb reparseDataBuffer
	var bytesReturned uint32

	err = windows.DeviceIoControl(
		h, windows.FSCTL_GET_REPARSE_POINT, nil, 0,
		rdb.BytePtr(), rdb.BytePtrSize(), &bytesReturned, nil)
	if err != nil {
		if err.(windows.Errno) == _ERROR_NOT_A_REPARSE_POINT {
			// Path is not a reparse point, so
			// not a UNIX socket either.
			return false, nil
		}

		return false, errors.Wrap(err, "unable to retrieve reparse data")
	}

	if rdb.ReparseTag == _IO_REPARSE_TAG_AF_UNIX {
		// Path is a UNIX socket.
		return true, nil
	}

	// Path is a reparse point,
	// but not a UNIX socket.
	return false, nil
}

// Returns true if the path references a named pipe.
func isWindowsPipePath(path string) bool {
	// If path matches \\*\pipe\* then it references a named pipe
	// and requires winio.DialPipe() rather than DialTimeout("unix").
	// Slashes and backslashes may be used interchangeably in the path.
	// Path separators may consist of multiple consecutive (back)slashes.
	pipePattern := strings.ReplaceAll("^[/]{2}[^/]+[/]+pipe[/]+", "/", `\\/`)
	ok, _ := regexp.MatchString(pipePattern, path)
	return ok
}

func windowsPipeDialer(path string) (net.Conn, error) {
	return winio.DialPipe(path, nil)
}

// Result of FSCTL_GET_REPARSE_POINT when the target is not a reparse point.
//
// See https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--4000-5999-
const _ERROR_NOT_A_REPARSE_POINT = 4390

// Reparse tag for UNIX sockets.
//
// See https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4
const _IO_REPARSE_TAG_AF_UNIX = 0x80000023

// Reparse point data buffer struct.
//
// Used to map the contents of the FSCTL_GET_REPARSE_POINT output buffer.
//
// See https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c3a420cb-8a72-4adf-87e8-eee95379d78f
type reparseDataBuffer struct {
	ReparseTag        uint32
	ReparseDataLength uint16
	Reserved          uint16
	dataBuffer        [windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE - 8]byte
}

// BytePtr returns a pointer to use as windows.DeviceIoControl() outBuffer.
func (rdb *reparseDataBuffer) BytePtr() *byte {
	return (*byte)(unsafe.Pointer(rdb))
}

// BytePtrSize returns a uint32 to use as windows.DeviceIoControl() outBufferSize.
func (rdb *reparseDataBuffer) BytePtrSize() uint32 {
	return uint32(unsafe.Sizeof(*rdb))
}

// GetReparseData returns the type-specific reparse data returned by windows.DeviceIoControl().
func (rdb *reparseDataBuffer) GetReparseData() []byte {
	return rdb.dataBuffer[:rdb.ReparseDataLength]
}
