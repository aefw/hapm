// Package ssh menyediakan SSH client untuk komunikasi dengan node HAProxy.
// Menggunakan golang.org/x/crypto/ssh sebagai transport layer.
package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// Client mendefinisikan kontrak SSH client yang digunakan oleh services
type Client interface {
	// RunCommand menjalankan perintah pada remote host melalui SSH
	RunCommand(ctx context.Context, conn *Connection, cmd string) (string, error)
	// UploadFile mengupload file ke remote host melalui SCP
	UploadFile(ctx context.Context, conn *Connection, localContent []byte, remotePath string) error
	// DownloadFile mengunduh isi file dari remote host
	DownloadFile(ctx context.Context, conn *Connection, remotePath string) ([]byte, error)
	// Ping mengetes koneksi SSH ke node (timeout singkat)
	Ping(ctx context.Context, conn *Connection) (time.Duration, error)
}

// Connection berisi parameter koneksi ke satu node
type Connection struct {
	Host       string
	Port       int
	User       string
	PrivateKey string // PEM format, plaintext (sudah didekripsi)
}

// Addr mengembalikan format host:port
func (c *Connection) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// sshClient adalah implementasi Client menggunakan golang.org/x/crypto/ssh
type sshClient struct {
	dialTimeout    time.Duration
	commandTimeout time.Duration
}

// NewClient membuat instance SSH Client baru dengan default timeout.
// commandTimeout digunakan untuk operasi ringan; operasi berat (provision, deploy)
// sebaiknya memanggil SetCommandTimeout atau menggunakan context dengan deadline.
func NewClient() Client {
	return &sshClient{
		dialTimeout:    10 * time.Second,
		commandTimeout: 10 * time.Minute, // cukup untuk apt-get install
	}
}

// buildConfig membangun *gossh.ClientConfig dari Connection
func (c *sshClient) buildConfig(conn *Connection) (*gossh.ClientConfig, error) {
	signer, err := gossh.ParsePrivateKey([]byte(conn.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("ssh: parse private key: %w", err)
	}

	cfg := &gossh.ClientConfig{
		User: conn.User,
		Auth: []gossh.AuthMethod{
			gossh.PublicKeys(signer),
		},
		// HostKeyCallback diset InsecureIgnoreHostKey untuk kemudahan self-hosted.
		// Produksi: bisa ditambahkan known_hosts checking.
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         c.dialTimeout,
	}
	return cfg, nil
}

// dial membuka koneksi SSH ke remote host dengan deadline
func (c *sshClient) dial(ctx context.Context, conn *Connection) (*gossh.Client, error) {
	cfg, err := c.buildConfig(conn)
	if err != nil {
		return nil, err
	}

	// Dial dengan context timeout
	dialer := &net.Dialer{Timeout: c.dialTimeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", conn.Addr())
	if err != nil {
		return nil, fmt.Errorf("ssh: dial %s: %w", conn.Addr(), err)
	}

	sshConn, chans, reqs, err := gossh.NewClientConn(tcpConn, conn.Addr(), cfg)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("ssh: handshake %s: %w", conn.Addr(), err)
	}

	return gossh.NewClient(sshConn, chans, reqs), nil
}

// RunCommand menjalankan single command pada remote host dan mengembalikan output-nya
func (c *sshClient) RunCommand(ctx context.Context, conn *Connection, cmd string) (string, error) {
	client, err := c.dial(ctx, conn)
	if err != nil {
		return "", err
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh: new session: %w", err)
	}
	defer sess.Close()

	// Set deadline dari context
	if deadline, ok := ctx.Deadline(); ok {
		_ = deadline // deadline ditangani via context cancel
	}

	var stdout, stderr strings.Builder
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	// Terapkan commandTimeout via context deadline jika belum ada
	runCtx := ctx
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, c.commandTimeout)
		defer cancel()
	}

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()

	select {
	case err := <-done:
		if err != nil {
			errMsg := strings.TrimSpace(stderr.String())
			if errMsg == "" {
				errMsg = err.Error()
			}
			// Kembalikan stdout meskipun command gagal; banyak tools (haproxy -c, apt-get, dll.)
			// menulis diagnostic ke stdout, dan caller perlu output ini untuk error reporting.
			return strings.TrimSpace(stdout.String()), fmt.Errorf("ssh: run command %q: %s", cmd, errMsg)
		}
	case <-runCtx.Done():
		sess.Signal(gossh.SIGTERM) //nolint:errcheck
		return "", fmt.Errorf("ssh: run command %q: timeout atau context cancelled", cmd)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// UploadFile mengupload content ke remotePath menggunakan SCP inline protocol.
// remotePath harus dapat ditulis oleh user SSH — untuk path sistem (misal /etc/haproxy/)
// upload ke /tmp terlebih dahulu lalu gunakan sudo mv dari caller.
func (c *sshClient) UploadFile(ctx context.Context, conn *Connection, localContent []byte, remotePath string) error {
	client, err := c.dial(ctx, conn)
	if err != nil {
		return err
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh: new session for scp: %w", err)
	}
	defer sess.Close()

	// Ekstrak filename dan direktori dari path
	parts := strings.Split(remotePath, "/")
	filename := parts[len(parts)-1]
	dir := strings.Join(parts[:len(parts)-1], "/")
	if dir == "" {
		dir = "."
	}

	// Capture stderr agar error message dari remote jelas (misal: permission denied)
	var stderr strings.Builder
	sess.Stderr = &stderr

	// Buka stdin pipe untuk SCP protocol
	w, err := sess.StdinPipe()
	if err != nil {
		return fmt.Errorf("ssh: stdin pipe: %w", err)
	}

	// Jalankan scp -t (sink mode) untuk menerima file
	if err := sess.Start(fmt.Sprintf("scp -t %s", dir)); err != nil {
		return fmt.Errorf("ssh: start scp: %w", err)
	}

	// Kirim SCP header: file mode, size, filename
	fmt.Fprintf(w, "C0644 %d %s\n", len(localContent), filename)
	if _, err := io.Copy(w, strings.NewReader(string(localContent))); err != nil {
		return fmt.Errorf("ssh: write content: %w", err)
	}
	fmt.Fprint(w, "\x00") // SCP end-of-file marker
	w.Close()

	if err := sess.Wait(); err != nil {
		errDetail := strings.TrimSpace(stderr.String())
		if errDetail != "" {
			return fmt.Errorf("ssh: scp upload ke %s gagal: %s", remotePath, errDetail)
		}
		return fmt.Errorf("ssh: scp upload ke %s gagal: %w", remotePath, err)
	}
	return nil
}

// DownloadFile mengunduh isi file dari remotePath pada remote host
func (c *sshClient) DownloadFile(ctx context.Context, conn *Connection, remotePath string) ([]byte, error) {
	output, err := c.RunCommand(ctx, conn, fmt.Sprintf("cat %s", remotePath))
	if err != nil {
		return nil, fmt.Errorf("ssh: download file %s: %w", remotePath, err)
	}
	return []byte(output), nil
}

// Ping mengetes koneksi SSH dan mengukur latency
func (c *sshClient) Ping(ctx context.Context, conn *Connection) (time.Duration, error) {
	start := time.Now()

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := c.RunCommand(pingCtx, conn, "echo pong")
	if err != nil {
		return 0, fmt.Errorf("ssh: ping failed: %w", err)
	}

	return time.Since(start), nil
}
