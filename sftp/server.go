package sftp

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"

	"github.com/pterodactyl/wings/config"
	"github.com/pterodactyl/wings/remote"
	"github.com/pterodactyl/wings/server"
)

const (
	// Default configuration values
	DefaultMaxConnections    = 500
	DefaultConnectionTimeout = 60 * 60 // seconds (increased to 60 minutes for large file transfers)
	DefaultPort              = 22
	DefaultAddress           = "0.0.0.0"
)

// Usernames all follow the same format, so don't even bother hitting the API if the username is not
// at least in the expected format. This is very basic protection against random bots finding the SFTP
// server and sending a flood of usernames.
var validUsernameRegexp = regexp.MustCompile(`^(?i)(.+)\.([a-z0-9]{8})$`)

//goland:noinspection GoNameStartsWithPackageName
type SFTPServer struct {
	manager      *server.Manager
	BasePath     string
	ReadOnly     bool
	Listen       string
	maxConns     int32
	activeConns  int32
	connTimeout  time.Duration
	shutdownChan chan struct{}
	shutdownOnce sync.Once
}

func New(m *server.Manager) *SFTPServer {
	cfg := config.Get().System

	// Use default configuration values for now
	// In the future, these could be configurable via config file
	maxConns := int32(DefaultMaxConnections)
	connTimeout := time.Duration(DefaultConnectionTimeout) * time.Second

	address := cfg.Sftp.Address
	if address == "" {
		address = DefaultAddress
		log.Info("SFTP address not configured, using default")
	}

	port := cfg.Sftp.Port
	if port <= 0 || port > 65535 {
		port = DefaultPort
		log.WithField("port", port).Warn("SFTP port out of range, using default")
	}

	listenAddr := address + ":" + strconv.Itoa(port)

	// Validate base path
	if cfg.Data == "" {
		log.Warn("SFTP base path not configured, using current directory")
		cfg.Data = "."
	}

	log.WithFields(log.Fields{
		"address":         address,
		"port":            port,
		"max_connections": maxConns,
		"timeout_seconds": connTimeout.Seconds(),
		"read_only":       cfg.Sftp.ReadOnly,
	}).Info("SFTP server configuration")

	return &SFTPServer{
		manager:      m,
		BasePath:     cfg.Data,
		ReadOnly:     cfg.Sftp.ReadOnly,
		Listen:       listenAddr,
		maxConns:     maxConns,
		connTimeout:  connTimeout,
		shutdownChan: make(chan struct{}),
	}
}

// Run starts the SFTP server and add a persistent listener to handle inbound
// SFTP connections. This will automatically generate an ED25519 key if one does
// not already exist on the system for host key verification purposes.
func (c *SFTPServer) Run() error {
	if _, err := os.Stat(c.PrivateKeyPath()); os.IsNotExist(err) {
		if err := c.generateED25519PrivateKey(); err != nil {
			return err
		}
	} else if err != nil {
		return errors.Wrap(err, "sftp: could not stat private key file")
	}
	pb, err := os.ReadFile(c.PrivateKeyPath())
	if err != nil {
		return errors.Wrap(err, "sftp: could not read private key file")
	}
	private, err := ssh.ParsePrivateKey(pb)
	if err != nil {
		return err
	}

	conf := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: []string{
				"curve25519-sha256", "curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha256",
			},
			Ciphers: []string{
				"aes128-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
				"aes128-ctr", "aes192-ctr", "aes256-ctr",
			},
			MACs: []string{
				"hmac-sha2-256-etm@openssh.com", "hmac-sha2-256",
			},
		},
		NoClientAuth: false,
		MaxAuthTries: 6,
		// Note: ConnectionTimeout is handled via SetDeadline on the net.Conn
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return c.makeCredentialsRequest(conn, remote.SftpAuthPassword, string(password))
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return c.makeCredentialsRequest(conn, remote.SftpAuthPublicKey, string(ssh.MarshalAuthorizedKey(key)))
		},
	}
	conf.AddHostKey(private)

	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}

	public := string(ssh.MarshalAuthorizedKey(private.PublicKey()))
	log.WithField("listen", c.Listen).WithField("public_key", strings.Trim(public, "\n")).Info("sftp server listening for connections")

	for {
		select {
		case <-c.shutdownChan:
			log.Info("sftp server shutting down")
			return nil
		default:
			// Set accept timeout to allow checking shutdown signal
			if tcpListener, ok := listener.(*net.TCPListener); ok {
				tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
			}

			conn, err := listener.Accept()
			if err != nil {
				// Check if it's a timeout error (expected for shutdown check)
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.WithField("error", err).Error("sftp: error accepting connection")
				continue
			}

			// Check connection limit
			if atomic.LoadInt32(&c.activeConns) >= c.maxConns {
				log.WithField("ip", conn.RemoteAddr().String()).Warn("sftp: connection limit reached, rejecting new connection")
				conn.Close()
				continue
			}

			atomic.AddInt32(&c.activeConns, 1)
			go func(conn net.Conn) {
				defer func() {
					conn.Close()
					atomic.AddInt32(&c.activeConns, -1)
				}()

				// Set read/write deadlines on the connection
				// Update deadlines periodically during large file transfers to avoid timeouts
				conn.SetReadDeadline(time.Now().Add(c.connTimeout))
				conn.SetWriteDeadline(time.Now().Add(c.connTimeout))

				// Set TCP keepalive to maintain connection for long uploads
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					tcpConn.SetKeepAlive(true)
					tcpConn.SetKeepAlivePeriod(30 * time.Second)
				}

				if err := c.AcceptInbound(conn, conf); err != nil {
					log.WithField("error", err).WithField("ip", conn.RemoteAddr().String()).Error("sftp: failed to accept inbound connection")
				}
			}(conn)
		}
	}
}

// AcceptInbound handles an inbound connection to the instance and determines if we should
// serve the request or not.
func (c *SFTPServer) AcceptInbound(conn net.Conn, config *ssh.ServerConfig) error {
	// Before beginning a handshake must be performed on the incoming net.Conn
	sconn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return errors.WithStack(err)
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	for ch := range chans {
		// If its not a session channel we just move on because its not something we
		// know how to handle at this point.
		if ch.ChannelType() != "session" {
			ch.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := ch.Accept()
		if err != nil {
			continue
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				// Channels have a type that is dependent on the protocol. For SFTP
				// this is "subsystem" with a payload that (should) be "sftp". Discard
				// anything else we receive ("pty", "shell", etc)
				req.Reply(req.Type == "subsystem" && string(req.Payload[4:]) == "sftp", nil)
			}
		}(requests)

		// If no UUID has been set on this inbound request then we can assume we
		// have screwed up something in the authentication code. This is a sanity
		// check, but should never be encountered (ideally...).
		//
		// This will also attempt to match a specific server out of the global server
		// store and return nil if there is no match.
		uuid := sconn.Permissions.Extensions["uuid"]
		srv := c.manager.Find(func(s *server.Server) bool {
			if uuid == "" {
				return false
			}
			return s.ID() == uuid
		})
		if srv == nil {
			continue
		}

		// Spin up a SFTP server instance for the authenticated user's server allowing
		// them access to the underlying filesystem.
		handler, err := NewHandler(sconn, srv)
		if err != nil {
			return errors.WithStackIf(err)
		}
		rs := sftp.NewRequestServer(channel, handler.Handlers())
		if err := rs.Serve(); err == io.EOF {
			_ = rs.Close()
		}
	}

	return nil
}

// Generates a new ED25519 private key that is used for host authentication when
// a user connects to the SFTP server.
func (c *SFTPServer) generateED25519PrivateKey() error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Wrap(err, "sftp: failed to generate ED25519 private key")
	}
	if err := os.MkdirAll(path.Dir(c.PrivateKeyPath()), 0o755); err != nil {
		return errors.Wrap(err, "sftp: could not create internal sftp data directory")
	}
	o, err := os.OpenFile(c.PrivateKeyPath(), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return errors.WithStack(err)
	}
	defer o.Close()

	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return errors.Wrap(err, "sftp: failed to marshal private key into bytes")
	}
	if err := pem.Encode(o, &pem.Block{Type: "PRIVATE KEY", Bytes: b}); err != nil {
		return errors.Wrap(err, "sftp: failed to write ED25519 private key to disk")
	}
	return nil
}

func (c *SFTPServer) makeCredentialsRequest(conn ssh.ConnMetadata, t remote.SftpAuthRequestType, p string) (*ssh.Permissions, error) {
	request := remote.SftpAuthRequest{
		Type:          t,
		User:          conn.User(),
		Pass:          p,
		IP:            conn.RemoteAddr().String(),
		SessionID:     conn.SessionID(),
		ClientVersion: conn.ClientVersion(),
	}

	logger := log.WithFields(log.Fields{
		"subsystem":  "sftp",
		"method":     request.Type,
		"username":   request.User,
		"ip":         request.IP,
		"session_id": request.SessionID,
	})

	logger.Debug("validating credentials for SFTP connection")

	if !validUsernameRegexp.MatchString(request.User) {
		logger.Warn("failed to validate user credentials (invalid format)")
		return nil, &remote.SftpInvalidCredentialsError{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.manager.Client().ValidateSftpCredentials(ctx, request)
	if err != nil {
		if _, ok := err.(*remote.SftpInvalidCredentialsError); ok {
			logger.Warn("failed to validate user credentials (invalid username or password)")
		} else if ctx.Err() == context.DeadlineExceeded {
			logger.Warn("authentication request timed out")
		} else {
			logger.WithField("error", err).Error("encountered an error while trying to validate user credentials")
		}
		return nil, err
	}

	logger.WithFields(log.Fields{
		"server":            resp.Server,
		"user_uuid":         resp.User,
		"permissions_count": len(resp.Permissions),
	}).Debug("credentials validated and matched to server instance")

	permissions := ssh.Permissions{
		Extensions: map[string]string{
			"ip":          conn.RemoteAddr().String(),
			"uuid":        resp.Server,
			"user":        resp.User,
			"permissions": strings.Join(resp.Permissions, ","),
		},
	}

	return &permissions, nil
}

// Shutdown gracefully shuts down the SFTP server
func (c *SFTPServer) Shutdown() {
	c.shutdownOnce.Do(func() {
		close(c.shutdownChan)
	})
}

// PrivateKeyPath returns the path the host private key for this server instance.
func (c *SFTPServer) PrivateKeyPath() string {
	return path.Join(c.BasePath, ".sftp/id_ed25519")
}
