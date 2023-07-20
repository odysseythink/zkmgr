package zkmgr

/*
TODO:
* make sure a ping response comes back in a reasonable time

Possible watcher events:
* zkEvent{Type: EventNotWatching, State: StateDisconnected, Path: path, Err: err}
*/

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// zkErrNoServer indicates that an operation cannot be completed
// because attempts to connect to all servers in the list failed.
var zkErrNoServer = errors.New("zk: could not connect to a server")

// zkErrInvalidPath indicates that an operation was being attempted on
// an invalid path. (e.g. empty path)
var zkErrInvalidPath = errors.New("zk: invalid path")

// DefaultLogger uses the stdlib log package for logging.
var DefaultLogger Logger = defaultLogger{}

const (
	bufferSize      = 1536 * 1024
	eventChanSize   = 6
	sendChanSize    = 16
	protectedPrefix = "_c_"
)

type watchType int

const (
	watchTypeData = iota
	watchTypeExist
	watchTypeChild
)

type watchPathType struct {
	path  string
	wType watchType
}

type Dialer func(network, address string, timeout time.Duration) (net.Conn, error)

// Logger is an interface that can be implemented to provide custom log output.
type Logger interface {
	Printf(string, ...interface{})
}

type authCreds struct {
	scheme string
	auth   []byte
}

type zkConn struct {
	lastZxid         int64
	sessionID        int64
	state            State // must be 32-bit aligned
	xid              uint32
	sessionTimeoutMs int32 // session timeout in milliseconds
	passwd           []byte

	dialer         Dialer
	hostProvider   HostProvider
	serverMu       sync.Mutex // protects server
	server         string     // remember the address/port of the current server
	conn           net.Conn
	eventChan      chan zkEvent
	eventCallback  zkEventCallback // may be nil
	shouldQuit     chan struct{}
	shouldQuitOnce sync.Once
	pingInterval   time.Duration
	recvTimeout    time.Duration
	connectTimeout time.Duration
	maxBufferSize  int

	creds   []authCreds
	credsMu sync.Mutex // protects server

	sendChan     chan *request
	requests     map[int32]*request // Xid -> pending request
	requestsLock sync.Mutex
	watchers     map[watchPathType][]chan zkEvent
	watchersLock sync.Mutex
	closeChan    chan struct{} // channel to tell send loop stop

	// Debug (used by unit tests)
	reconnectLatch   chan struct{}
	setWatchLimit    int
	setWatchCallback func([]*setWatchesRequest)

	// Debug (for recurring re-auth hang)
	debugCloseRecvLoop bool
	resendZkAuthFn     func(context.Context, *zkConn) error

	logger  Logger
	logInfo bool // true if information messages are logged; false if only errors are logged

	buf []byte
}

// connOption represents a connection option.
type connOption func(c *zkConn)

type request struct {
	xid        int32
	opcode     int32
	pkt        interface{}
	recvStruct interface{}
	recvChan   chan response

	// Because sending and receiving happen in separate go routines, there's
	// a possible race condition when creating watches from outside the read
	// loop. We must ensure that a watcher gets added to the list synchronously
	// with the response from the server on any request that creates a watch.
	// In order to not hard code the watch logic for each opcode in the recv
	// loop the caller can use recvFunc to insert some synchronously code
	// after a response.
	recvFunc func(*request, *responseHeader, error)
}

type response struct {
	zxid int64
	err  error
}

type zkEvent struct {
	Type   EventType
	State  State
	Path   string // For non-session events, the path of the watched node.
	Err    error
	Server string // For connection events
}

// HostProvider is used to represent a set of hosts a ZooKeeper client should connect to.
// It is an analog of the Java equivalent:
// http://svn.apache.org/viewvc/zookeeper/trunk/src/java/main/org/apache/zookeeper/client/HostProvider.java?view=markup
type HostProvider interface {
	// Init is called first, with the servers specified in the connection string.
	Init(servers []string) error
	// Len returns the number of servers.
	Len() int
	// Next returns the next server to connect to. retryStart will be true if we've looped through
	// all known servers without Connected() being called.
	Next() (server string, retryStart bool)
	// Notify the HostProvider of a successful connection.
	Connected()
}

// ConnectWithDialer establishes a new connection to a pool of zookeeper servers
// using a custom Dialer. See Connect for further information about session timeout.
// This method is deprecated and provided for compatibility: use the WithDialer option instead.
func zkConnectWithDialer(servers []string, sessionTimeout time.Duration, dialer Dialer) (*zkConn, <-chan zkEvent, error) {
	return zkConnect(servers, sessionTimeout, zkWithDialer(dialer))
}

// Connect establishes a new connection to a pool of zookeeper
// servers. The provided session timeout sets the amount of time for which
// a session is considered valid after losing connection to a server. Within
// the session timeout it's possible to reestablish a connection to a different
// server and keep the same session. This is means any ephemeral nodes and
// watches are maintained.
func zkConnect(servers []string, sessionTimeout time.Duration, options ...connOption) (*zkConn, <-chan zkEvent, error) {
	if len(servers) == 0 {
		return nil, nil, errors.New("zk: server list must not be empty")
	}

	srvs := FormatServers(servers)

	// Randomize the order of the servers to avoid creating hotspots
	stringShuffle(srvs)

	ec := make(chan zkEvent, eventChanSize)
	conn := &zkConn{
		dialer:         net.DialTimeout,
		hostProvider:   &DNSHostProvider{},
		conn:           nil,
		state:          zkStateDisconnected,
		eventChan:      ec,
		shouldQuit:     make(chan struct{}),
		connectTimeout: 1 * time.Second,
		sendChan:       make(chan *request, sendChanSize),
		requests:       make(map[int32]*request),
		watchers:       make(map[watchPathType][]chan zkEvent),
		passwd:         emptyPassword,
		logger:         DefaultLogger,
		logInfo:        true, // default is true for backwards compatability
		buf:            make([]byte, bufferSize),
		resendZkAuthFn: resendZkAuth,
	}

	// Set provided options.
	for _, option := range options {
		option(conn)
	}

	if err := conn.hostProvider.Init(srvs); err != nil {
		return nil, nil, err
	}

	conn.setTimeouts(int32(sessionTimeout / time.Millisecond))
	// TODO: This context should be passed in by the caller to be the connection lifecycle context.
	ctx := context.Background()

	go func() {
		conn.loop(ctx)
		conn.flushRequests(zkErrClosing)
		conn.invalidateWatches(zkErrClosing)
		close(conn.eventChan)
	}()
	return conn, ec, nil
}

// zkWithDialer returns a connection option specifying a non-default Dialer.
func zkWithDialer(dialer Dialer) connOption {
	return func(c *zkConn) {
		c.dialer = dialer
	}
}

// zkWithHostProvider returns a connection option specifying a non-default HostProvider.
func zkWithHostProvider(hostProvider HostProvider) connOption {
	return func(c *zkConn) {
		c.hostProvider = hostProvider
	}
}

// zkWithLogger returns a connection option specifying a non-default Logger
func zkWithLogger(logger Logger) connOption {
	return func(c *zkConn) {
		c.logger = logger
	}
}

// zkWithLogInfo returns a connection option specifying whether or not information messages
// shoud be logged.
func zkWithLogInfo(logInfo bool) connOption {
	return func(c *zkConn) {
		c.logInfo = logInfo
	}
}

// EventCallback is a function that is called when an Event occurs.
type zkEventCallback func(zkEvent)

// zkWithEventCallback returns a connection option that specifies an event
// callback.
// The callback must not block - doing so would delay the ZK go routines.
func zkWithEventCallback(cb zkEventCallback) connOption {
	return func(c *zkConn) {
		c.eventCallback = cb
	}
}

// zkWithMaxBufferSize sets the maximum buffer size used to read and decode
// packets received from the Zookeeper server. The standard Zookeeper client for
// Java defaults to a limit of 1mb. For backwards compatibility, this Go client
// defaults to unbounded unless overridden via this option. A value that is zero
// or negative indicates that no limit is enforced.
//
// This is meant to prevent resource exhaustion in the face of potentially
// malicious data in ZK. It should generally match the server setting (which
// also defaults ot 1mb) so that clients and servers agree on the limits for
// things like the size of data in an individual znode and the total size of a
// transaction.
//
// For production systems, this should be set to a reasonable value (ideally
// that matches the server configuration). For ops tooling, it is handy to use a
// much larger limit, in order to do things like clean-up problematic state in
// the ZK tree. For example, if a single znode has a huge number of children, it
// is possible for the response to a "list children" operation to exceed this
// buffer size and cause errors in clients. The only way to subsequently clean
// up the tree (by removing superfluous children) is to use a client configured
// with a larger buffer size that can successfully query for all of the child
// names and then remove them. (Note there are other tools that can list all of
// the child names without an increased buffer size in the client, but they work
// by inspecting the servers' transaction logs to enumerate children instead of
// sending an online request to a server.
func zkWithMaxBufferSize(maxBufferSize int) connOption {
	return func(c *zkConn) {
		c.maxBufferSize = maxBufferSize
	}
}

// zkWithMaxConnBufferSize sets maximum buffer size used to send and encode
// packets to Zookeeper server. The standard Zookeepeer client for java defaults
// to a limit of 1mb. This option should be used for non-standard server setup
// where znode is bigger than default 1mb.
func zkWithMaxConnBufferSize(maxBufferSize int) connOption {
	return func(c *zkConn) {
		c.buf = make([]byte, maxBufferSize)
	}
}

// Close will submit a close request with ZK and signal the connection to stop
// sending and receiving packets.
func (c *zkConn) Close() {
	c.shouldQuitOnce.Do(func() {
		close(c.shouldQuit)

		select {
		case <-c.queueRequest(opClose, &closeRequest{}, &closeResponse{}, nil):
		case <-time.After(time.Second):
		}
	})
}

// State returns the current state of the connection.
func (c *zkConn) State() State {
	return State(atomic.LoadInt32((*int32)(&c.state)))
}

// SessionID returns the current session id of the connection.
func (c *zkConn) SessionID() int64 {
	return atomic.LoadInt64(&c.sessionID)
}

// SetLogger sets the logger to be used for printing errors.
// Logger is an interface provided by this package.
func (c *zkConn) SetLogger(l Logger) {
	c.logger = l
}

func (c *zkConn) setTimeouts(sessionTimeoutMs int32) {
	c.sessionTimeoutMs = sessionTimeoutMs
	sessionTimeout := time.Duration(sessionTimeoutMs) * time.Millisecond
	c.recvTimeout = sessionTimeout * 2 / 3
	c.pingInterval = c.recvTimeout / 2
}

func (c *zkConn) setState(state State) {
	atomic.StoreInt32((*int32)(&c.state), int32(state))
	c.sendEvent(zkEvent{Type: zkEventSession, State: state, Server: c.Server()})
}

func (c *zkConn) sendEvent(evt zkEvent) {
	if c.eventCallback != nil {
		c.eventCallback(evt)
	}

	select {
	case c.eventChan <- evt:
	default:
		// panic("zk: event channel full - it must be monitored and never allowed to be full")
	}
}

func (c *zkConn) connect() error {
	var retryStart bool
	for {
		c.serverMu.Lock()
		c.server, retryStart = c.hostProvider.Next()
		c.serverMu.Unlock()

		c.setState(zkStateConnecting)

		if retryStart {
			c.flushUnsentRequests(zkErrNoServer)
			select {
			case <-time.After(time.Second):
				// pass
			case <-c.shouldQuit:
				c.setState(zkStateDisconnected)
				c.flushUnsentRequests(zkErrClosing)
				return zkErrClosing
			}
		}

		zkConn, err := c.dialer("tcp", c.Server(), c.connectTimeout)
		if err == nil {
			c.conn = zkConn
			c.setState(zkStateConnected)
			if c.logInfo {
				c.logger.Printf("connected to %s", c.Server())
			}
			return nil
		}

		c.logger.Printf("failed to connect to %s: %v", c.Server(), err)
	}
}

func (c *zkConn) sendRequest(
	opcode int32,
	req interface{},
	res interface{},
	recvFunc func(*request, *responseHeader, error),
) (
	<-chan response,
	error,
) {
	rq := &request{
		xid:        c.nextXid(),
		opcode:     opcode,
		pkt:        req,
		recvStruct: res,
		recvChan:   make(chan response, 1),
		recvFunc:   recvFunc,
	}

	if err := c.sendData(rq); err != nil {
		return nil, err
	}

	return rq.recvChan, nil
}

func (c *zkConn) loop(ctx context.Context) {
	for {
		if err := c.connect(); err != nil {
			// c.Close() was called
			return
		}

		err := c.authenticate()
		switch {
		case err == zkErrSessionExpired:
			c.logger.Printf("authentication failed: %s", err)
			c.invalidateWatches(err)
		case err != nil && c.conn != nil:
			c.logger.Printf("authentication failed: %s", err)
			c.conn.Close()
		case err == nil:
			if c.logInfo {
				c.logger.Printf("authenticated: id=%d, timeout=%d", c.SessionID(), c.sessionTimeoutMs)
			}
			c.hostProvider.Connected()        // mark success
			c.closeChan = make(chan struct{}) // channel to tell send loop stop

			var wg sync.WaitGroup

			wg.Add(1)
			go func() {
				defer c.conn.Close() // causes recv loop to EOF/exit
				defer wg.Done()

				if err := c.resendZkAuthFn(ctx, c); err != nil {
					c.logger.Printf("error in resending auth creds: %v", err)
					return
				}

				if err := c.sendLoop(); err != nil || c.logInfo {
					c.logger.Printf("send loop terminated: %v", err)
				}
			}()

			wg.Add(1)
			go func() {
				defer close(c.closeChan) // tell send loop to exit
				defer wg.Done()

				var err error
				if c.debugCloseRecvLoop {
					err = errors.New("DEBUG: close recv loop")
				} else {
					err = c.recvLoop(c.conn)
				}
				if err != io.EOF || c.logInfo {
					c.logger.Printf("recv loop terminated: %v", err)
				}
				if err == nil {
					panic("zk: recvLoop should never return nil error")
				}
			}()

			c.sendSetWatches()
			wg.Wait()
		}

		c.setState(zkStateDisconnected)

		select {
		case <-c.shouldQuit:
			c.flushRequests(zkErrClosing)
			return
		default:
		}

		if err != zkErrSessionExpired {
			err = zkErrConnectionClosed
		}
		c.flushRequests(err)

		if c.reconnectLatch != nil {
			select {
			case <-c.shouldQuit:
				return
			case <-c.reconnectLatch:
			}
		}
	}
}

func (c *zkConn) flushUnsentRequests(err error) {
	for {
		select {
		default:
			return
		case req := <-c.sendChan:
			req.recvChan <- response{-1, err}
		}
	}
}

// Send error to all pending requests and clear request map
func (c *zkConn) flushRequests(err error) {
	c.requestsLock.Lock()
	for _, req := range c.requests {
		req.recvChan <- response{-1, err}
	}
	c.requests = make(map[int32]*request)
	c.requestsLock.Unlock()
}

// Send error to all watchers and clear watchers map
func (c *zkConn) invalidateWatches(err error) {
	c.watchersLock.Lock()
	defer c.watchersLock.Unlock()

	if len(c.watchers) >= 0 {
		for pathType, watchers := range c.watchers {
			ev := zkEvent{Type: zkEventNotWatching, State: zkStateDisconnected, Path: pathType.path, Err: err}
			for _, ch := range watchers {
				ch <- ev
				close(ch)
			}
		}
		c.watchers = make(map[watchPathType][]chan zkEvent)
	}
}

func (c *zkConn) sendSetWatches() {
	c.watchersLock.Lock()
	defer c.watchersLock.Unlock()

	if len(c.watchers) == 0 {
		return
	}

	// NB: A ZK server, by default, rejects packets >1mb. So, if we have too
	// many watches to reset, we need to break this up into multiple packets
	// to avoid hitting that limit. Mirroring the Java client behavior: we are
	// conservative in that we limit requests to 128kb (since server limit is
	// is actually configurable and could conceivably be configured smaller
	// than default of 1mb).
	limit := 128 * 1024
	if c.setWatchLimit > 0 {
		limit = c.setWatchLimit
	}

	var reqs []*setWatchesRequest
	var req *setWatchesRequest
	var sizeSoFar int

	n := 0
	for pathType, watchers := range c.watchers {
		if len(watchers) == 0 {
			continue
		}
		addlLen := 4 + len(pathType.path)
		if req == nil || sizeSoFar+addlLen > limit {
			if req != nil {
				// add to set of requests that we'll send
				reqs = append(reqs, req)
			}
			sizeSoFar = 28 // fixed overhead of a set-watches packet
			req = &setWatchesRequest{
				RelativeZxid: c.lastZxid,
				DataWatches:  make([]string, 0),
				ExistWatches: make([]string, 0),
				ChildWatches: make([]string, 0),
			}
		}
		sizeSoFar += addlLen
		switch pathType.wType {
		case watchTypeData:
			req.DataWatches = append(req.DataWatches, pathType.path)
		case watchTypeExist:
			req.ExistWatches = append(req.ExistWatches, pathType.path)
		case watchTypeChild:
			req.ChildWatches = append(req.ChildWatches, pathType.path)
		}
		n++
	}
	if n == 0 {
		return
	}
	if req != nil { // don't forget any trailing packet we were building
		reqs = append(reqs, req)
	}

	if c.setWatchCallback != nil {
		c.setWatchCallback(reqs)
	}

	go func() {
		res := &setWatchesResponse{}
		// TODO: Pipeline these so queue all of them up before waiting on any
		// response. That will require some investigation to make sure there
		// aren't failure modes where a blocking write to the channel of requests
		// could hang indefinitely and cause this goroutine to leak...
		for _, req := range reqs {
			_, err := c.request(opSetWatches, req, res, nil)
			if err != nil {
				c.logger.Printf("Failed to set previous watches: %v", err)
				break
			}
		}
	}()
}

func (c *zkConn) authenticate() error {
	buf := make([]byte, 256)

	// Encode and send a connect request.
	n, err := encodePacket(buf[4:], &connectRequest{
		ProtocolVersion: protocolVersion,
		LastZxidSeen:    c.lastZxid,
		TimeOut:         c.sessionTimeoutMs,
		SessionID:       c.SessionID(),
		Passwd:          c.passwd,
	})
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint32(buf[:4], uint32(n))

	c.conn.SetWriteDeadline(time.Now().Add(c.recvTimeout * 10))
	_, err = c.conn.Write(buf[:n+4])
	c.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}

	// Receive and decode a connect response.
	c.conn.SetReadDeadline(time.Now().Add(c.recvTimeout * 10))
	_, err = io.ReadFull(c.conn, buf[:4])
	c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}

	blen := int(binary.BigEndian.Uint32(buf[:4]))
	if cap(buf) < blen {
		buf = make([]byte, blen)
	}

	_, err = io.ReadFull(c.conn, buf[:blen])
	if err != nil {
		return err
	}

	r := connectResponse{}
	_, err = decodePacket(buf[:blen], &r)
	if err != nil {
		return err
	}
	if r.SessionID == 0 {
		atomic.StoreInt64(&c.sessionID, int64(0))
		c.passwd = emptyPassword
		c.lastZxid = 0
		c.setState(zkStateExpired)
		return zkErrSessionExpired
	}

	atomic.StoreInt64(&c.sessionID, r.SessionID)
	c.setTimeouts(r.TimeOut)
	c.passwd = r.Passwd
	c.setState(zkStateHasSession)

	return nil
}

func (c *zkConn) sendData(req *request) error {
	header := &requestHeader{req.xid, req.opcode}
	n, err := encodePacket(c.buf[4:], header)
	if err != nil {
		req.recvChan <- response{-1, err}
		return nil
	}

	n2, err := encodePacket(c.buf[4+n:], req.pkt)
	if err != nil {
		req.recvChan <- response{-1, err}
		return nil
	}

	n += n2

	binary.BigEndian.PutUint32(c.buf[:4], uint32(n))

	c.requestsLock.Lock()
	select {
	case <-c.closeChan:
		req.recvChan <- response{-1, zkErrConnectionClosed}
		c.requestsLock.Unlock()
		return zkErrConnectionClosed
	default:
	}
	c.requests[req.xid] = req
	c.requestsLock.Unlock()

	c.conn.SetWriteDeadline(time.Now().Add(c.recvTimeout))
	_, err = c.conn.Write(c.buf[:n+4])
	c.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		req.recvChan <- response{-1, err}
		c.conn.Close()
		return err
	}

	return nil
}

func (c *zkConn) sendLoop() error {
	pingTicker := time.NewTicker(c.pingInterval)
	defer pingTicker.Stop()

	for {
		select {
		case req := <-c.sendChan:
			if err := c.sendData(req); err != nil {
				return err
			}
		case <-pingTicker.C:
			n, err := encodePacket(c.buf[4:], &requestHeader{Xid: -2, Opcode: opPing})
			if err != nil {
				panic("zk: opPing should never fail to serialize")
			}

			binary.BigEndian.PutUint32(c.buf[:4], uint32(n))

			c.conn.SetWriteDeadline(time.Now().Add(c.recvTimeout))
			_, err = c.conn.Write(c.buf[:n+4])
			c.conn.SetWriteDeadline(time.Time{})
			if err != nil {
				c.conn.Close()
				return err
			}
		case <-c.closeChan:
			return nil
		}
	}
}

func (c *zkConn) recvLoop(conn net.Conn) error {
	sz := bufferSize
	if c.maxBufferSize > 0 && sz > c.maxBufferSize {
		sz = c.maxBufferSize
	}
	buf := make([]byte, sz)
	for {
		// package length
		if err := conn.SetReadDeadline(time.Now().Add(c.recvTimeout)); err != nil {
			c.logger.Printf("failed to set connection deadline: %v", err)
		}
		_, err := io.ReadFull(conn, buf[:4])
		if err != nil {
			return fmt.Errorf("failed to read from connection: %v", err)
		}

		blen := int(binary.BigEndian.Uint32(buf[:4]))
		if cap(buf) < blen {
			if c.maxBufferSize > 0 && blen > c.maxBufferSize {
				return fmt.Errorf("received packet from server with length %d, which exceeds max buffer size %d", blen, c.maxBufferSize)
			}
			buf = make([]byte, blen)
		}

		_, err = io.ReadFull(conn, buf[:blen])
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			return err
		}

		res := responseHeader{}
		_, err = decodePacket(buf[:16], &res)
		if err != nil {
			return err
		}

		if res.Xid == -1 {
			res := &watcherEvent{}
			_, err := decodePacket(buf[16:blen], res)
			if err != nil {
				return err
			}
			ev := zkEvent{
				Type:  res.Type,
				State: res.State,
				Path:  res.Path,
				Err:   nil,
			}
			c.sendEvent(ev)
			wTypes := make([]watchType, 0, 2)
			switch res.Type {
			case zkEventNodeCreated:
				wTypes = append(wTypes, watchTypeExist)
			case zkEventNodeDeleted, zkEventNodeDataChanged:
				wTypes = append(wTypes, watchTypeExist, watchTypeData, watchTypeChild)
			case zkEventNodeChildrenChanged:
				wTypes = append(wTypes, watchTypeChild)
			}
			c.watchersLock.Lock()
			for _, t := range wTypes {
				wpt := watchPathType{res.Path, t}
				if watchers := c.watchers[wpt]; watchers != nil && len(watchers) > 0 {
					for _, ch := range watchers {
						ch <- ev
						close(ch)
					}
					delete(c.watchers, wpt)
				}
			}
			c.watchersLock.Unlock()
		} else if res.Xid == -2 {
			// Ping response. Ignore.
		} else if res.Xid < 0 {
			c.logger.Printf("Xid < 0 (%d) but not ping or watcher event", res.Xid)
		} else {
			if res.Zxid > 0 {
				c.lastZxid = res.Zxid
			}

			c.requestsLock.Lock()
			req, ok := c.requests[res.Xid]
			if ok {
				delete(c.requests, res.Xid)
			}
			c.requestsLock.Unlock()

			if !ok {
				c.logger.Printf("Response for unknown request with xid %d", res.Xid)
			} else {
				if res.Err != 0 {
					err = res.Err.toError()
				} else {
					_, err = decodePacket(buf[16:blen], req.recvStruct)
				}
				if req.recvFunc != nil {
					req.recvFunc(req, &res, err)
				}
				req.recvChan <- response{res.Zxid, err}
				if req.opcode == opClose {
					return io.EOF
				}
			}
		}
	}
}

func (c *zkConn) nextXid() int32 {
	return int32(atomic.AddUint32(&c.xid, 1) & 0x7fffffff)
}

func (c *zkConn) addWatcher(path string, watchType watchType) <-chan zkEvent {
	c.watchersLock.Lock()
	defer c.watchersLock.Unlock()

	ch := make(chan zkEvent, 1)
	wpt := watchPathType{path, watchType}
	c.watchers[wpt] = append(c.watchers[wpt], ch)
	return ch
}

func (c *zkConn) queueRequest(opcode int32, req interface{}, res interface{}, recvFunc func(*request, *responseHeader, error)) <-chan response {
	rq := &request{
		xid:        c.nextXid(),
		opcode:     opcode,
		pkt:        req,
		recvStruct: res,
		recvChan:   make(chan response, 2),
		recvFunc:   recvFunc,
	}

	switch opcode {
	case opClose:
		// always attempt to send close ops.
		select {
		case c.sendChan <- rq:
		case <-time.After(c.connectTimeout * 2):
			c.logger.Printf("gave up trying to send opClose to server")
			rq.recvChan <- response{-1, zkErrConnectionClosed}
		}
	default:
		// otherwise avoid deadlocks for dumb clients who aren't aware that
		// the ZK connection is closed yet.
		select {
		case <-c.shouldQuit:
			rq.recvChan <- response{-1, zkErrConnectionClosed}
		case c.sendChan <- rq:
			// check for a tie
			select {
			case <-c.shouldQuit:
				// maybe the caller gets this, maybe not- we tried.
				rq.recvChan <- response{-1, zkErrConnectionClosed}
			default:
			}
		}
	}
	return rq.recvChan
}

func (c *zkConn) request(opcode int32, req interface{}, res interface{}, recvFunc func(*request, *responseHeader, error)) (int64, error) {
	r := <-c.queueRequest(opcode, req, res, recvFunc)
	select {
	case <-c.shouldQuit:
		// queueRequest() can be racy, double-check for the race here and avoid
		// a potential data-race. otherwise the client of this func may try to
		// access `res` fields concurrently w/ the async response processor.
		// NOTE: callers of this func should check for (at least) ErrConnectionClosed
		// and avoid accessing fields of the response object if such error is present.
		return -1, zkErrConnectionClosed
	default:
		return r.zxid, r.err
	}
}

func (c *zkConn) AddAuth(scheme string, auth []byte) error {
	_, err := c.request(opSetAuth, &setAuthRequest{Type: 0, Scheme: scheme, Auth: auth}, &setAuthResponse{}, nil)

	if err != nil {
		return err
	}

	// Remember authdata so that it can be re-submitted on reconnect
	//
	// FIXME(prozlach): For now we treat "userfoo:passbar" and "userfoo:passbar2"
	// as two different entries, which will be re-submitted on reconnet. Some
	// research is needed on how ZK treats these cases and
	// then maybe switch to something like "map[username] = password" to allow
	// only single password for given user with users being unique.
	obj := authCreds{
		scheme: scheme,
		auth:   auth,
	}

	c.credsMu.Lock()
	c.creds = append(c.creds, obj)
	c.credsMu.Unlock()

	return nil
}

func (c *zkConn) Children(path string) ([]string, *Stat, error) {
	if err := validatePath(path, false); err != nil {
		return nil, nil, err
	}

	res := &getChildren2Response{}
	_, err := c.request(opGetChildren2, &getChildren2Request{Path: path, Watch: false}, res, nil)
	if err == zkErrConnectionClosed {
		return nil, nil, err
	}
	return res.Children, &res.Stat, err
}

func (c *zkConn) ChildrenW(path string) ([]string, *Stat, <-chan zkEvent, error) {
	if err := validatePath(path, false); err != nil {
		return nil, nil, nil, err
	}

	var ech <-chan zkEvent
	res := &getChildren2Response{}
	_, err := c.request(opGetChildren2, &getChildren2Request{Path: path, Watch: true}, res, func(req *request, res *responseHeader, err error) {
		if err == nil {
			ech = c.addWatcher(path, watchTypeChild)
		}
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return res.Children, &res.Stat, ech, err
}

func (c *zkConn) Get(path string) ([]byte, *Stat, error) {
	if err := validatePath(path, false); err != nil {
		return nil, nil, err
	}

	res := &getDataResponse{}
	_, err := c.request(opGetData, &getDataRequest{Path: path, Watch: false}, res, nil)
	if err == zkErrConnectionClosed {
		return nil, nil, err
	}
	return res.Data, &res.Stat, err
}

// GetW returns the contents of a znode and sets a watch
func (c *zkConn) GetW(path string) ([]byte, *Stat, <-chan zkEvent, error) {
	if err := validatePath(path, false); err != nil {
		return nil, nil, nil, err
	}

	var ech <-chan zkEvent
	res := &getDataResponse{}
	_, err := c.request(opGetData, &getDataRequest{Path: path, Watch: true}, res, func(req *request, res *responseHeader, err error) {
		if err == nil {
			ech = c.addWatcher(path, watchTypeData)
		}
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return res.Data, &res.Stat, ech, err
}

func (c *zkConn) Set(path string, data []byte, version int32) (*Stat, error) {
	if err := validatePath(path, false); err != nil {
		return nil, err
	}

	res := &setDataResponse{}
	_, err := c.request(opSetData, &SetDataRequest{path, data, version}, res, nil)
	if err == zkErrConnectionClosed {
		return nil, err
	}
	return &res.Stat, err
}

func (c *zkConn) Create(path string, data []byte, flags int32, acl []zkACL) (string, error) {
	if err := validatePath(path, flags&zkFlagSequence == zkFlagSequence); err != nil {
		return "", err
	}

	res := &createResponse{}
	_, err := c.request(opCreate, &CreateRequest{path, data, acl, flags}, res, nil)
	if err == zkErrConnectionClosed {
		return "", err
	}
	return res.Path, err
}

func (c *zkConn) CreateContainer(path string, data []byte, flags int32, acl []zkACL) (string, error) {
	if err := validatePath(path, flags&zkFlagSequence == zkFlagSequence); err != nil {
		return "", err
	}
	if flags&zkFlagTTL != zkFlagTTL {
		return "", zkErrInvalidFlags
	}

	res := &createResponse{}
	_, err := c.request(opCreateContainer, &CreateContainerRequest{path, data, acl, flags}, res, nil)
	return res.Path, err
}

func (c *zkConn) CreateTTL(path string, data []byte, flags int32, acl []zkACL, ttl time.Duration) (string, error) {
	if err := validatePath(path, flags&zkFlagSequence == zkFlagSequence); err != nil {
		return "", err
	}
	if flags&zkFlagTTL != zkFlagTTL {
		return "", zkErrInvalidFlags
	}

	res := &createResponse{}
	_, err := c.request(opCreateTTL, &CreateTTLRequest{path, data, acl, flags, ttl.Milliseconds()}, res, nil)
	return res.Path, err
}

// CreateProtectedEphemeralSequential fixes a race condition if the server crashes
// after it creates the node. On reconnect the session may still be valid so the
// ephemeral node still exists. Therefore, on reconnect we need to check if a node
// with a GUID generated on create exists.
func (c *zkConn) CreateProtectedEphemeralSequential(path string, data []byte, acl []zkACL) (string, error) {
	if err := validatePath(path, true); err != nil {
		return "", err
	}

	var guid [16]byte
	_, err := io.ReadFull(rand.Reader, guid[:16])
	if err != nil {
		return "", err
	}
	guidStr := fmt.Sprintf("%x", guid)

	parts := strings.Split(path, "/")
	parts[len(parts)-1] = fmt.Sprintf("%s%s-%s", protectedPrefix, guidStr, parts[len(parts)-1])
	rootPath := strings.Join(parts[:len(parts)-1], "/")
	protectedPath := strings.Join(parts, "/")

	var newPath string
	for i := 0; i < 3; i++ {
		newPath, err = c.Create(protectedPath, data, zkFlagEphemeral|zkFlagSequence, acl)
		switch err {
		case zkErrSessionExpired:
			// No need to search for the node since it can't exist. Just try again.
		case zkErrConnectionClosed:
			children, _, err := c.Children(rootPath)
			if err != nil {
				return "", err
			}
			for _, p := range children {
				parts := strings.Split(p, "/")
				if pth := parts[len(parts)-1]; strings.HasPrefix(pth, protectedPrefix) {
					if g := pth[len(protectedPrefix) : len(protectedPrefix)+32]; g == guidStr {
						return rootPath + "/" + p, nil
					}
				}
			}
		case nil:
			return newPath, nil
		default:
			return "", err
		}
	}
	return "", err
}

func (c *zkConn) Delete(path string, version int32) error {
	if err := validatePath(path, false); err != nil {
		return err
	}

	_, err := c.request(opDelete, &DeleteRequest{path, version}, &deleteResponse{}, nil)
	return err
}

func (c *zkConn) Exists(path string) (bool, *Stat, error) {
	if err := validatePath(path, false); err != nil {
		return false, nil, err
	}

	res := &existsResponse{}
	_, err := c.request(opExists, &existsRequest{Path: path, Watch: false}, res, nil)
	if err == zkErrConnectionClosed {
		return false, nil, err
	}
	exists := true
	if err == zkErrNoNode {
		exists = false
		err = nil
	}
	return exists, &res.Stat, err
}

func (c *zkConn) ExistsW(path string) (bool, *Stat, <-chan zkEvent, error) {
	if err := validatePath(path, false); err != nil {
		return false, nil, nil, err
	}

	var ech <-chan zkEvent
	res := &existsResponse{}
	_, err := c.request(opExists, &existsRequest{Path: path, Watch: true}, res, func(req *request, res *responseHeader, err error) {
		if err == nil {
			ech = c.addWatcher(path, watchTypeData)
		} else if err == zkErrNoNode {
			ech = c.addWatcher(path, watchTypeExist)
		}
	})
	exists := true
	if err == zkErrNoNode {
		exists = false
		err = nil
	}
	if err != nil {
		return false, nil, nil, err
	}
	return exists, &res.Stat, ech, err
}

func (c *zkConn) GetACL(path string) ([]zkACL, *Stat, error) {
	if err := validatePath(path, false); err != nil {
		return nil, nil, err
	}

	res := &getAclResponse{}
	_, err := c.request(opGetAcl, &getAclRequest{Path: path}, res, nil)
	if err == zkErrConnectionClosed {
		return nil, nil, err
	}
	return res.Acl, &res.Stat, err
}
func (c *zkConn) SetACL(path string, acl []zkACL, version int32) (*Stat, error) {
	if err := validatePath(path, false); err != nil {
		return nil, err
	}

	res := &setAclResponse{}
	_, err := c.request(opSetAcl, &setAclRequest{Path: path, Acl: acl, Version: version}, res, nil)
	if err == zkErrConnectionClosed {
		return nil, err
	}
	return &res.Stat, err
}

func (c *zkConn) Sync(path string) (string, error) {
	if err := validatePath(path, false); err != nil {
		return "", err
	}

	res := &syncResponse{}
	_, err := c.request(opSync, &syncRequest{Path: path}, res, nil)
	if err == zkErrConnectionClosed {
		return "", err
	}
	return res.Path, err
}

type MultiResponse struct {
	Stat   *Stat
	String string
	Error  error
}

// Multi executes multiple ZooKeeper operations or none of them. The provided
// ops must be one of *CreateRequest, *DeleteRequest, *SetDataRequest, or
// *CheckVersionRequest.
func (c *zkConn) Multi(ops ...interface{}) ([]MultiResponse, error) {
	req := &multiRequest{
		Ops:        make([]multiRequestOp, 0, len(ops)),
		DoneHeader: multiHeader{Type: -1, Done: true, Err: -1},
	}
	for _, op := range ops {
		var opCode int32
		switch op.(type) {
		case *CreateRequest:
			opCode = opCreate
		case *SetDataRequest:
			opCode = opSetData
		case *DeleteRequest:
			opCode = opDelete
		case *CheckVersionRequest:
			opCode = opCheck
		default:
			return nil, fmt.Errorf("unknown operation type %T", op)
		}
		req.Ops = append(req.Ops, multiRequestOp{multiHeader{opCode, false, -1}, op})
	}
	res := &multiResponse{}
	_, err := c.request(opMulti, req, res, nil)
	if err == zkErrConnectionClosed {
		return nil, err
	}
	mr := make([]MultiResponse, len(res.Ops))
	for i, op := range res.Ops {
		mr[i] = MultiResponse{Stat: op.Stat, String: op.String, Error: op.Err.toError()}
	}
	return mr, err
}

// IncrementalReconfig is the zookeeper reconfiguration api that allows adding and removing servers
// by lists of members. For more info refer to the ZK documentation.
//
// An optional version allows for conditional reconfigurations, -1 ignores the condition.
//
// Returns the new configuration znode stat.
func (c *zkConn) IncrementalReconfig(joining, leaving []string, version int64) (*Stat, error) {
	// TODO: validate the shape of the member string to give early feedback.
	request := &reconfigRequest{
		JoiningServers: []byte(strings.Join(joining, ",")),
		LeavingServers: []byte(strings.Join(leaving, ",")),
		CurConfigId:    version,
	}

	return c.internalReconfig(request)
}

// Reconfig is the non-incremental update functionality for Zookeeper where the list provided
// is the entire new member list. For more info refer to the ZK documentation.
//
// An optional version allows for conditional reconfigurations, -1 ignores the condition.
//
// Returns the new configuration znode stat.
func (c *zkConn) Reconfig(members []string, version int64) (*Stat, error) {
	request := &reconfigRequest{
		NewMembers:  []byte(strings.Join(members, ",")),
		CurConfigId: version,
	}

	return c.internalReconfig(request)
}

func (c *zkConn) internalReconfig(request *reconfigRequest) (*Stat, error) {
	response := &reconfigReponse{}
	_, err := c.request(opReconfig, request, response, nil)
	return &response.Stat, err
}

// Server returns the current or last-connected server name.
func (c *zkConn) Server() string {
	c.serverMu.Lock()
	defer c.serverMu.Unlock()
	return c.server
}

func resendZkAuth(ctx context.Context, c *zkConn) error {
	shouldCancel := func() bool {
		select {
		case <-c.shouldQuit:
			return true
		case <-c.closeChan:
			return true
		default:
			return false
		}
	}

	c.credsMu.Lock()
	defer c.credsMu.Unlock()

	if c.logInfo {
		c.logger.Printf("re-submitting `%d` credentials after reconnect", len(c.creds))
	}

	for _, cred := range c.creds {
		// return early before attempting to send request.
		if shouldCancel() {
			return nil
		}
		// do not use the public API for auth since it depends on the send/recv loops
		// that are waiting for this to return
		resChan, err := c.sendRequest(
			opSetAuth,
			&setAuthRequest{Type: 0,
				Scheme: cred.scheme,
				Auth:   cred.auth,
			},
			&setAuthResponse{},
			nil, /* recvFunc*/
		)
		if err != nil {
			return fmt.Errorf("failed to send auth request: %v", err)
		}

		var res response
		select {
		case res = <-resChan:
		case <-c.closeChan:
			c.logger.Printf("recv closed, cancel re-submitting credentials")
			return nil
		case <-c.shouldQuit:
			c.logger.Printf("should quit, cancel re-submitting credentials")
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
		if res.err != nil {
			return fmt.Errorf("failed conneciton setAuth request: %v", res.err)
		}
	}

	return nil
}
