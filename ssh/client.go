package ssh

import (
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// How long should we pause between a running command
	// and reading the output.
	pause = (time.Millisecond*1200)
)

type Client struct {
	address string
	session *ssh.Session
	connection *ssh.Client
	stdin io.Writer
	stdout io.Reader
	stderr io.Reader
}

func NewClient(addr string) *Client {
	return &Client{
		address: addr,
		session: nil,
		connection: nil,
		stdin: nil,
		stdout: nil,
		stderr: nil,
	}
}

func (asa *Client) Connect(username, passwd string) error {
	sshConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(passwd),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		HostKeyAlgorithms: []string{"ssh-rsa"}, // TODO: allow user to pass in algorithms.
	}

	var err error
	asa.connection, err = ssh.Dial("tcp", fmt.Sprintf("%s:22", asa.address), sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to device: %v", err)
	}

	asa.session, err = asa.connection.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create new sessions: %v", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err = asa.session.RequestPty("xterm", 80, 80, modes); err != nil {
		return fmt.Errorf("request for pseudo terminal failed: %s", err)
	}
	asa.stdin, err = asa.session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %v", err)
	}
	asa.stdout, err = asa.session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdin pipe: %v", err)
	}

	if err = asa.session.Shell(); err != nil {
		return fmt.Errorf("failed to create shell: %v", err)
	}

	return nil
}

// SendCommand runs a command on the device and returns the output as a string.
// A newline is added to the command by the function, so caller does not have to.
func (asa *Client) SendCommand(cmd string) (string, error) {
	cmdNl := fmt.Sprintf("%s\n", cmd)
	asa.stdin.Write([]byte(cmdNl))

	time.Sleep(pause)

	result := make([]byte, 10000)
	n, err := asa.stdout.Read(result)
	if err != nil {
		return "", fmt.Errorf("failed to read command result: %v", err)
	}

	return string(result[:n]), nil
}

// Enable takes the enable password for the device and changes the prompt context to enable mode.
// Returns an error if it fails to get into the enable context.
func (asa *Client) Enable(passwd string) error {
	asa.stdin.Write([]byte("en\n"))
	time.Sleep(time.Second)
	asa.stdin.Write([]byte(fmt.Sprintf("%s\n", passwd)))

	time.Sleep(pause)

	result := make([]byte, 10000)
	n, err := asa.stdout.Read(result)
	if err != nil {
		return fmt.Errorf("failed to read enable command result: %v", err)
	}
	// Check that we got to the enable prompt.
	if string(result[n-2]) != "#" {
		return fmt.Errorf("failed to get enable: %s", string(result[n-2]))
	}
	return nil
}

func (asa *Client) Close() {
	asa.connection.Close()
	asa.session.Close()
}
