package sadv

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
)

// SASLauthdVerifyPassword connects to saslauthd socket at path and
// autneticates. If the return value is not an error, then authentication
// was successful. The string response is the response from saslauthd. It is
// usually not needed but can be useful for debugging purposes.
func SASLauthdVerifyPassword(path, user, password, service, realm,
	clientAddr string) (string, error) {
	if service == "" {
		service = "imap"
	}
	if user == "" || password == "" {
		return "", ErrUserPasswordRequired
	}
	psr := os.Getenv("PATH_SASLAUTHD_RUNDIR")
	if path == "" {
		path = psr + "/mux"
		// TODO: is it always mux or is it configurable at saslauthd build time?
	}
	if psr == "" {
		path = "/var/run/saslauthd/mux"
	}
	query := &bytes.Buffer{}
	err := writeAuthDstring(query, user)
	if err != nil {
		return "", err
	}
	err = writeAuthDstring(query, password)
	if err != nil {
		return "", err
	}
	err = writeAuthDstring(query, service)
	if err != nil {
		return "", err
	}
	err = writeAuthDstring(query, realm)
	if err != nil {
		return "", err
	}
	err = writeAuthDstring(query, clientAddr)
	if err != nil {
		return "", err
	}

	// Connect to path unix socket.
	c, err := net.Dial("unix", path)
	if err != nil {
		return "", err
	}
	defer c.Close()
	n, err := c.Write(query.Bytes())
	if n != query.Len() {
		return "", io.ErrShortWrite
	}
	var cnt uint16
	err = binary.Read(c, binary.BigEndian, &cnt)
	if err != nil {
		return "", err
	}
	response := make([]byte, cnt)
	n, err = io.ReadAtLeast(c, response, int(cnt))
	if err != nil {
		return "", err
	}
	if n != int(cnt) {
		return "", ErrReadingResponse
	}
	if !bytes.HasPrefix(response, []byte("OK")) {
		return string(response), ErrAuthFailed
	}

	return string(response), nil
}

// writeAuthDstring writes the string with size prefix for saslauthd or zero
// if the string is empty.
func writeAuthDstring(b *bytes.Buffer, s string) error {
	l := uint16(len(s))
	err := binary.Write(b, binary.BigEndian, l)
	if err != nil {
		return err
	}
	if len(s) == 0 {
		return nil
	}
	_, err = b.WriteString(s)
	if err != nil {
		return err
	}
	return nil
}

// Error is a sadv error.
type Error string

func (e Error) Error() string {
	return string(e)
}

const (
	// ErrUserPasswordRequired is the error for requiring user and password.
	ErrUserPasswordRequired = Error("user and password are required")

	// ErrReadingResponse is the error when reading fails.
	ErrReadingResponse = Error("error reading response")

	// ErrAuthFailed is the error when auth fails.
	ErrAuthFailed = Error("authentication failed")
)
