package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"

	"github.com/jackc/puddle/v2"
	log "github.com/sirupsen/logrus"
	"github.com/xvzc/SpoofDPI/dns"
	"github.com/xvzc/SpoofDPI/packet"
	"github.com/xvzc/SpoofDPI/util"
)

type Proxy struct {
	addr           string
	port           int
	timeout        int
	resolver       *dns.DnsResolver
	windowSize     int
	allowedPattern []*regexp.Regexp
	bufferSize     int
	bufferProvider bufferProvider
}

type bufferWrapper interface {
	getBuffer() []byte
	release()
}

type simpleBufferWrapper struct {
	buffer []byte
}

type puddleManagedBufferWrapper struct {
	resource *puddle.Resource[*[]byte]
}

func (s *simpleBufferWrapper) getBuffer() []byte {
	return s.buffer
}

func (s *simpleBufferWrapper) release() {
	// do nothing
}

func (s *puddleManagedBufferWrapper) getBuffer() []byte {
	return *s.resource.Value()
}

func (s *puddleManagedBufferWrapper) release() {
	s.resource.Release()
}

type BufferProvider bufferProvider
type bufferProvider interface {
	getBufferHolder() (bufferWrapper, error)
	putBufferHolder(wrapper bufferWrapper)
}

type simpleBufferProvider struct {
	requestedSize int
}

func (s *simpleBufferProvider) getBufferHolder() (bufferWrapper, error) {
	return &simpleBufferWrapper{
		buffer: make([]byte, s.requestedSize),
	}, nil
}

func (s *simpleBufferProvider) putBufferHolder(wrapper bufferWrapper) {
	wrapper.release()
	return
}

type poolBufferProvider struct {
	pool *puddle.Pool[*[]byte]
}

func (p *poolBufferProvider) getBufferHolder() (bufferWrapper, error) {
	acquire, err := p.pool.Acquire(context.TODO())
	if err != nil {
		return nil, err
	}
	return &puddleManagedBufferWrapper{
		resource: acquire,
	}, nil
}

func (p *poolBufferProvider) putBufferHolder(wrapper bufferWrapper) {
	wrapper.release()
	return
}

func newPoolBufferProvider(maxPoolSize int32, requestedBufferSize int32) (*poolBufferProvider, error) {
	pool, err := puddle.NewPool(&puddle.Config[*[]byte]{
		Constructor: func(context context.Context) (res *[]byte, err error) {
			bytes := make([]byte, requestedBufferSize)
			return &bytes, nil
		},
		Destructor: func(res *[]byte) {
			*res = nil
		},
		MaxSize: maxPoolSize,
	},
	)
	if err != nil {
		return nil, err
	}
	return &poolBufferProvider{
		pool: pool,
	}, nil
}

func newSimpleBufferProvider(requestedBufferSize int32) *simpleBufferProvider {
	return &simpleBufferProvider{
		requestedSize: int(requestedBufferSize),
	}
}

func New(config *util.Config) (*Proxy, error) {
	provider, err := newBufferProvider(config)
	if err != nil {
		return nil, err
	}
	return &Proxy{
		addr:           *config.Addr,
		port:           *config.Port,
		timeout:        *config.Timeout,
		windowSize:     *config.WindowSize,
		allowedPattern: config.AllowedPattern,
		resolver:       dns.NewResolver(config),
		bufferSize:     *config.BufferSize,
		bufferProvider: provider,
	}, nil
}

func newBufferProvider(config *util.Config) (bufferProvider, error) {
	if *config.UseSharedBufferPool {
		maxPoolSize := config.SharedBufferPoolSize
		return newPoolBufferProvider(int32(*maxPoolSize), int32(*config.BufferSize))
	} else {
		return newSimpleBufferProvider(int32(*config.BufferSize)), nil
	}
}

func (pxy *Proxy) Start() {
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(pxy.addr), Port: pxy.port})
	if err != nil {
		log.Fatal("[PROXY] Error creating listener: ", err)
		os.Exit(1)
	}

	if pxy.timeout > 0 {
		log.Println(fmt.Sprintf("[PROXY] Connection timeout is set to %dms", pxy.timeout))
	}

	log.Println("[PROXY] Created a listener on port", pxy.port)
	if len(pxy.allowedPattern) > 0 {
		log.Println("[PROXY] Number of white-listed pattern:", len(pxy.allowedPattern))
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("[PROXY] Error accepting connection: ", err)
			continue
		}

		go func() {
			pkt, err := packet.NewHttpPacketFromReader(conn)
			if err != nil {
				return
			}

			log.Debug("[PROXY] Request from ", conn.RemoteAddr(), "\n\n", string(pkt.Raw()))

			if err != nil {
				log.Debug("[PROXY] Error while parsing request: ", string(pkt.Raw()))
				conn.Close()
				return
			}

			if !pkt.IsValidMethod() {
				log.Debug("[PROXY] Unsupported method: ", pkt.Method())
				conn.Close()
				return
			}

			matched := pxy.patternMatches([]byte(pkt.Domain()))
			useSystemDns := !matched

			ip, err := pxy.resolver.Lookup(pkt.Domain(), useSystemDns)
			if err != nil {
				log.Debug("[PROXY] Error while dns lookup: ", pkt.Domain(), " ", err)
				conn.Write([]byte(pkt.Version() + " 502 Bad Gateway\r\n\r\n"))
				conn.Close()
				return
			}

			// Avoid recursively querying self
			if pkt.Port() == strconv.Itoa(pxy.port) && isLoopedRequest(net.ParseIP(ip)) {
				log.Error("[PROXY] Looped request has been detected. aborting.")
				conn.Close()
				return
			}

			if pkt.IsConnectMethod() {
				log.Debug("[PROXY] Start HTTPS")
				pxy.handleHttps(conn.(*net.TCPConn), matched, pkt, ip)
			} else {
				log.Debug("[PROXY] Start HTTP")
				pxy.handleHttp(conn.(*net.TCPConn), pkt, ip)
			}
		}()
	}
}

func (pxy *Proxy) patternMatches(bytes []byte) bool {
	if pxy.allowedPattern == nil {
		return true
	}

	for _, pattern := range pxy.allowedPattern {
		if pattern.Match(bytes) {
			return true
		}
	}

	return false
}

func isLoopedRequest(ip net.IP) bool {
	// we don't handle IPv6 at all it seems
	if ip.To4() == nil {
		return false
	}

	if ip.IsLoopback() {
		return true
	}

	// Get list of available addresses
	// See `ip -4 addr show`
	addr, err := net.InterfaceAddrs() // needs AF_NETLINK on linux
	if err != nil {
		log.Error("[PROXY] Error while getting addresses of our network interfaces: ", err)
		return false
	}

	for _, addr := range addr {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil && ipnet.IP.To4().Equal(ip) {
				return true
			}
		}
	}

	return false
}
