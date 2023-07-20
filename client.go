package zkmgr

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"mlib.com/mrun"
)

// DefaultACL is the default ACL to use for creating znodes.
var (
	DefaultACL            = zkWorldACL(zkPermAll)
	ErrInvalidCredentials = errors.New("invalid credentials provided")
	ErrClientClosed       = errors.New("client service closed")
	ErrNotRegistered      = errors.New("not registered")
	ErrNodeNotFound       = errors.New("node not found")
)

const (
	// DefaultConnectTimeout is the default timeout to establish a connection to
	// a ZooKeeper node.
	DefaultConnectTimeout = 2 * time.Second
	// DefaultSessionTimeout is the default timeout to keep the current
	// ZooKeeper session alive during a temporary disconnect.
	DefaultSessionTimeout = 5 * time.Second
)

// Service holds the root path, service name and instance identifying data you
// want to publish to ZooKeeper.
type Service struct {
	Path string // discovery namespace, example: /myorganization/myplatform/
	Name string // service name, example: addscv
	Data []byte // instance data to store for discovery, example: 10.0.2.10:80
	node string // Client will record the ephemeral node name so we can deregister
}

// Client is a wrapper around a lower level ZooKeeper client implementation.
type Client interface {
	GetWEntry(path string) (string, <-chan zkEvent, error)
	// GetEntries should query the provided path in ZooKeeper, place a watch on
	// it and retrieve data from its current child nodes.
	GetEntries(path string) ([]string, <-chan zkEvent, error)
	// GetNodesAndEntries should query the provided path in ZooKeeper, place a watch on
	// it and retrieve data from its current child nodes.
	GetNodesAndEntries(path string) (map[string]string, <-chan zkEvent, error)
	GetWNodesAndEntries(path string) (map[string]string, map[string]<-chan zkEvent, <-chan zkEvent, error)
	// CreateParentNodes should try to create the path in case it does not exist
	// yet on ZooKeeper.
	CreateParentNodes(path string) error
	// Register a service with ZooKeeper.
	Register(path, name, data string) error
	// Register a service with ZooKeeper.
	RegisterDirect(path, name, data string) error
	// Deregister a service with ZooKeeper.
	Deregister(path, name string) error
	// Stop should properly shutdown the client implementation
	Stop()
	AddInstancer(path string, cb InstancerCallBack, errcb InstancerErrCallBack, childcb ChildCallBack) error
	StopInstancer(path string) error
	DeleteFullpath(path string) error
}

type clientConfig struct {
	acl             []zkACL
	credentials     []byte
	connectTimeout  time.Duration
	sessionTimeout  time.Duration
	rootNodePayload [][]byte
	eventHandler    func(zkEvent)
}

// Option functions enable friendly APIs.
type Option func(*clientConfig) error

type client struct {
	*zkConn
	eventc <-chan zkEvent
	clientConfig
	clientMgr   mrun.ModuleMgr
	services    map[string]*Service
	instanceres map[string]*Instancer
	exitOnce    sync.Once
	clientEventWatcher
}

// ACL returns an Option specifying a non-default ACL for creating parent nodes.
func ACLFunc(acl []zkACL) Option {
	return func(c *clientConfig) error {
		c.acl = acl
		return nil
	}
}

// Credentials returns an Option specifying a user/password combination which
// the client will use to authenticate itself with.
func Credentials(user, pass string) Option {
	return func(c *clientConfig) error {
		if user == "" || pass == "" {
			return ErrInvalidCredentials
		}
		c.credentials = []byte(user + ":" + pass)
		return nil
	}
}

// ConnectTimeout returns an Option specifying a non-default connection timeout
// when we try to establish a connection to a ZooKeeper server.
func ConnectTimeout(t time.Duration) Option {
	return func(c *clientConfig) error {
		if t.Seconds() < 1 {
			return errors.New("invalid connect timeout (minimum value is 1 second)")
		}
		c.connectTimeout = t
		return nil
	}
}

// SessionTimeout returns an Option specifying a non-default session timeout.
func SessionTimeout(t time.Duration) Option {
	return func(c *clientConfig) error {
		if t.Seconds() < 1 {
			return errors.New("invalid session timeout (minimum value is 1 second)")
		}
		c.sessionTimeout = t
		return nil
	}
}

// Payload returns an Option specifying non-default data values for each znode
// created by CreateParentNodes.
func Payload(payload [][]byte) Option {
	return func(c *clientConfig) error {
		c.rootNodePayload = payload
		return nil
	}
}

// EventHandler returns an Option specifying a callback function to handle
// incoming zkEvent payloads (ZooKeeper connection events).
func EventHandler(handler func(zkEvent)) Option {
	return func(c *clientConfig) error {
		c.eventHandler = handler
		return nil
	}
}

// NewClient returns a ZooKeeper client with a connection to the server cluster.
// It will return an error if the server cluster cannot be resolved.
func NewClient(servers []string, options ...Option) (Client, error) {
	log.SetFlags(log.Lmicroseconds | log.Lshortfile)
	c := &client{}
	err := c.Init(servers, options)
	if err != nil {
		log.Printf("[E]client init failed:%v\n", err)
		return nil, err
	}
	return c, nil
}

func (c *client) Init(args ...interface{}) error {
	if len(args) != 2 {
		log.Printf("[E] invalid args\n")
		return errors.New("invalid args")
	}
	if servers, ok := args[0].([]string); !ok || servers == nil {
		log.Printf("[E]args[0] must be stringlist to define servers")
		return errors.New("args[0] must be stringlist to define servers")
	} else {
		if options, ok := args[1].([]Option); !ok {
			log.Printf("[E]args[1] must be Option list to define Option")
			return errors.New("args[1] must be Option list to define Option")
		} else {
			defaultEventHandler := func(event zkEvent) {
				if event.Err != nil {
					log.Printf("[W]eventtype(%s) server(%s) state(%s) err(%v)\n", event.Type.String(), event.Server, event.State.String(), event.Err)
				}
			}
			c.clientConfig = clientConfig{
				acl:            DefaultACL,
				connectTimeout: DefaultConnectTimeout,
				sessionTimeout: DefaultSessionTimeout,
				eventHandler:   defaultEventHandler,
			}
			for _, option := range options {
				if err := option(&c.clientConfig); err != nil {
					log.Printf("[E]option failed:%v\n", err)
					return err
				}
			}
			// dialer overrides the default ZooKeeper library Dialer so we can configure
			// the connectTimeout. The current library has a hardcoded value of 1 second
			// and there are reports of race conditions, due to slow DNS resolvers and
			// other network latency issues.
			dialer := func(network, address string, _ time.Duration) (net.Conn, error) {
				return net.DialTimeout(network, address, c.clientConfig.connectTimeout)
			}
			var err error
			c.zkConn, c.eventc, err = zkConnect(servers, c.clientConfig.sessionTimeout, withLogger(), zkWithDialer(dialer))

			if err != nil {
				log.Printf("[E]zkConnect failed:%v\n", err)
				return err
			}

			if len(c.clientConfig.credentials) > 0 {
				err = c.zkConn.AddAuth("digest", c.clientConfig.credentials)
				if err != nil {
					c.zkConn.Close()
					log.Printf("[E]zkConn.AddAuth failed:%v\n", err)
					return err
				}
			}
			c.services = make(map[string]*Service)
			c.instanceres = make(map[string]*Instancer)

			// Start listening for incoming Event payloads and callback the set
			// eventHandler.
			c.clientMgr.Register(&c.clientEventWatcher, nil, c)
			err = c.clientMgr.Init()
			if err != nil {
				log.Printf("[E]client init failed:%v\n", err)
				c.zkConn.Close()
				return err
			}

			return nil
		}
	}

}

// CreateParentNodes implements the ZooKeeper Client interface.
func (c *client) CreateParentNodes(path string) error {
	if c.zkConn == nil {
		return ErrClientClosed
	}
	if path[0] != '/' {
		log.Printf("[E]path(%s) not begin with / charater\n", path)
		return zkErrInvalidPath
	}
	payload := []byte("")
	pathString := ""
	pathNodes := strings.Split(path, "/")
	for i := 1; i < len(pathNodes); i++ {
		if pathNodes[i] == "" {
			continue
		}
		if i <= len(c.rootNodePayload) {
			payload = c.rootNodePayload[i-1]
		} else {
			payload = []byte("")
		}
		pathString += "/" + pathNodes[i]
		_, err := c.Create(pathString, payload, 0, c.acl)
		// not being able to create the node because it exists or not having
		// sufficient rights is not an issue. It is ok for the node to already
		// exist and/or us to only have read rights
		if err != nil && err != zkErrNodeExists && err != zkErrNoAuth {
			log.Printf("[E]path(%s) create failed:%v", pathString, err)
			return err
		}
	}
	return nil
}

// GetEntries implements the ZooKeeper Client interface.
func (c *client) GetEntries(path string) ([]string, <-chan zkEvent, error) {
	// retrieve list of child nodes for given path and add watch to path
	znodes, _, eventc, err := c.ChildrenW(path)

	if err != nil {
		return nil, eventc, err
	}

	var resp []string
	for _, znode := range znodes {
		// retrieve payload for child znode and add to response array
		if data, _, err := c.Get(path + "/" + znode); err == nil {
			resp = append(resp, string(data))
		}
	}
	return resp, eventc, nil
}

// GetNodesAndEntries implements the ZooKeeper Client interface.
func (c *client) GetNodesAndEntries(path string) (map[string]string, <-chan zkEvent, error) {
	// retrieve list of child nodes for given path and add watch to path
	znodes, _, eventc, err := c.ChildrenW(path)

	if err != nil {
		return nil, eventc, err
	}

	resp := make(map[string]string)
	for _, znode := range znodes {
		// retrieve payload for child znode and add to response array
		if data, _, err := c.Get(path + "/" + znode); err == nil {
			resp[path+"/"+znode] = string(data)
		}
	}
	return resp, eventc, nil
}

// GetWNodesAndEntries implements the ZooKeeper Client interface.
func (c *client) GetWNodesAndEntries(path string) (map[string]string, map[string]<-chan zkEvent, <-chan zkEvent, error) {
	// retrieve list of child nodes for given path and add watch to path
	znodes, _, eventc, err := c.ChildrenW(path)

	if err != nil {
		return nil, nil, eventc, err
	}

	resp := make(map[string]string)
	respc := make(map[string]<-chan zkEvent)
	for _, znode := range znodes {
		// retrieve payload for child znode and add to response array
		if data, _, childc, err := c.GetW(path + "/" + znode); err == nil {
			resp[path+"/"+znode] = string(data)
			respc[path+"/"+znode] = childc
		}
	}
	return resp, respc, eventc, nil
}

// GetWEntry implements the ZooKeeper Client interface.
func (c *client) GetWEntry(path string) (string, <-chan zkEvent, error) {
	data, _, eventc, err := c.GetW(path)
	return string(data), eventc, err
}

// Register implements the ZooKeeper Client interface.
func (c *client) Register(path, name, data string) error {
	log.Printf("[I]zk register(%s/%s) data(%s)\n", path, name, data)
	if path[len(path)-1] != '/' {
		path += "/"
	}
	fullpath := path + name
	if c.services != nil && len(c.services) > 0 {
		for k, _ := range c.services {
			if k == fullpath {
				// already exists
				found, stat, err := c.Exists(path)
				if err != nil {
					log.Printf("[E]Exists zk node(%s) failed:%v\n", fullpath, err)
					return fmt.Errorf("Exists zk node(%s) failed:%v", fullpath, err)
				}
				if !found {
					break
				} else {
					_, err := c.Set(fullpath, []byte(data), stat.Version)
					if err != nil {
						log.Printf("[E]set zk node(%s) failed:%v\n", fullpath, err)
						if err := c.Delete(fullpath, stat.Version); err != nil {
							log.Printf("[E]delete zk node(%s) failed:%v\n", fullpath, err)

						}
						delete(c.services, fullpath)
						return fmt.Errorf("set zk node(%s) failed:%v", fullpath, err)
					} else {
						log.Printf("[I]success update exists zk node(%s)\n", fullpath)
						return nil
					}
				}

			}
		}
	}

	s := &Service{
		Path: path,
		Name: name,
		Data: []byte(data),
	}

	if err := c.CreateParentNodes(fullpath); err != nil {
		log.Printf("[E]CreateParentNodes zk node(%s) failed:%v\n", fullpath, err)
		return fmt.Errorf("CreateParentNodes zk node(%s) failed:%v", fullpath, err)
	}
	if fullpath[len(fullpath)-1] != '/' {
		fullpath += "/"
	}
	node, err := c.CreateProtectedEphemeralSequential(fullpath, s.Data, c.acl)
	if err != nil {
		log.Printf("[E]CreateProtectedEphemeralSequential zk node(%s) failed:%v\n", fullpath, err)
		return fmt.Errorf("CreateProtectedEphemeralSequential zk node(%s) failed:%v", fullpath, err)
	}
	s.node = node
	c.services[fullpath] = s
	return nil

}

// Register implements the ZooKeeper Client interface.
func (c *client) RegisterDirect(path, name, data string) error {
	if path[len(path)-1] != '/' {
		path += "/"
	}
	fullpath := path + name
	if fullpath[len(fullpath)-1] == '/' {
		fullpath = fullpath[:len(fullpath)-1]
	}
	if c.services != nil && len(c.services) > 0 {
		for k, _ := range c.services {
			if k == fullpath {
				// already exists
				found, stat, err := c.Exists(path)
				if err != nil {
					log.Printf("[E]Exists zk node(%s) failed:%v\n", fullpath, err)
					return fmt.Errorf("Exists zk node(%s) failed:%v", fullpath, err)
				}
				if !found {
					break
				} else {
					_, err := c.Set(fullpath, []byte(data), stat.Version)
					if err != nil {
						log.Printf("[E]set zk node(%s) failed:%v\n", fullpath, err)
						if err := c.Delete(fullpath, stat.Version); err != nil {
							log.Printf("[E]delete zk node(%s) failed:%v\n", fullpath, err)

						}
						delete(c.services, fullpath)
						return fmt.Errorf("set zk node(%s) failed:%v", fullpath, err)
					} else {
						log.Printf("[I]success update exists zk node(%s)\n", fullpath)
						return nil
					}
				}

			}
		}
	}

	s := &Service{
		Path: path,
		Name: name,
		Data: []byte(data),
	}

	if s.Path[len(s.Path)-1] == '/' {
		s.Path = s.Path[0 : len(s.Path)-1]
	}

	if err := c.CreateParentNodes(s.Path); err != nil {
		return err
	}

	node, err := c.Create(fullpath, s.Data, zkFlagEphemeral, c.acl)
	if err != nil {
		return err
	}
	s.node = node
	c.services[fullpath] = s
	return nil
}

// Deregister implements the ZooKeeper Client interface.
func (c *client) Deregister(path, name string) error {
	if path[len(path)-1] != '/' {
		path += "/"
	}
	fullpath := path + name
	if fullpath[len(fullpath)-1] == '/' {
		fullpath = fullpath[:len(fullpath)-1]
	}
	if len(c.services) == 0 {
		log.Printf("[E]no services register\n")
		return fmt.Errorf("no services register")
	}
	if _, ok := c.services[fullpath]; !ok {
		log.Printf("[E]this service(%s) not register\n", fullpath)
		return fmt.Errorf("this service(%s) not register", fullpath)
	}

	found, stat, err := c.Exists(fullpath)
	if err != nil {
		log.Printf("[E]get service(%s) exists failed:%v\n", fullpath, err)
		return fmt.Errorf("get service(%s) exists failed:%v", fullpath, err)
	}
	if !found {
		log.Printf("[E]service(%s) node not exists\n", fullpath)
		return fmt.Errorf("service(%s) node not exists", fullpath)
	}
	if err := c.Delete(fullpath, stat.Version); err != nil {
		log.Printf("[E]service(%s) node Delete failed:%v\n", fullpath, err)
		return fmt.Errorf("service(%s) node Delete failed:%v", fullpath, err)
	}
	delete(c.services, fullpath)
	return nil
}

func (c *client) DeleteFullpath(fullpath string) error {
	log.Printf("[D]fullpath=%s\n", fullpath)
	if fullpath[len(fullpath)-1] == '/' {
		fullpath = fullpath[:len(fullpath)-1]
	}
	if len(c.services) == 0 {
		log.Printf("[E]no services register\n")
		return fmt.Errorf("no services register")
	}
	if _, ok := c.services[fullpath]; !ok {
		log.Printf("[E]this service(%s) not register\n", fullpath)
		return fmt.Errorf("this service(%s) not register", fullpath)
	}

	found, stat, err := c.Exists(fullpath)
	if err != nil {
		log.Printf("[E]get service(%s) exists failed:%v\n", fullpath, err)
		return fmt.Errorf("get service(%s) exists failed:%v", fullpath, err)
	}
	if !found {
		log.Printf("[E]service(%s) node not exists\n", fullpath)
		return fmt.Errorf("service(%s) node not exists", fullpath)
	}
	if err := c.Delete(fullpath, stat.Version); err != nil {
		log.Printf("[E]service(%s) node Delete failed:%v\n", fullpath, err)
		return fmt.Errorf("service(%s) node Delete failed:%v", fullpath, err)
	}
	delete(c.services, fullpath)
	return nil
}

// Stop implements the ZooKeeper Client interface.
func (c *client) Stop() {
	c.exitOnce.Do(func() {
		if c.zkConn != nil {
			c.zkConn.Close()
		}
	})
	c.clientMgr.Destroy()
}

func (c *client) AddInstancer(path string, cb InstancerCallBack, errcb InstancerErrCallBack, childcb ChildCallBack) error {
	if _, ok := c.instanceres[path]; ok {
		return nil
	}
	ins, err := NewInstancer(c, path, cb, errcb, childcb)
	if err != nil {
		log.Printf("[E]failed to new path(%s) instancer:%v\n", path, err)
		return fmt.Errorf("failed to new path(%s) instancer:%v", path, err)
	}
	c.instanceres[path] = ins
	return nil
}

func (c *client) StopInstancer(path string) error {
	if _, ok := c.instanceres[path]; !ok {
		log.Printf("[E]path(%s) instancer not exist\n", path)
		return fmt.Errorf("path(%s) instancer not exist", path)
	}
	c.instanceres[path].Stop()
	delete(c.instanceres, path)
	return nil
}

type clientEventWatcher struct {
	cli *client
}

func (w *clientEventWatcher) Init(args ...interface{}) error {
	if len(args) != 1 {
		log.Printf("[E] invalid args\n")
		return errors.New("invalid args")
	}
	if cli, ok := args[0].(*client); !ok || cli == nil {
		log.Printf("[E]args[0] must be client pointer")
		return errors.New("args[0] must be client pointer")
	} else {
		w.cli = cli
		if w.cli.eventc == nil {
			log.Printf("[E]client init failed, not have eventc")
			return errors.New("client init failed, not have eventc")
		}
		return nil
	}
}

func (w *clientEventWatcher) RunOnce(ctx context.Context) error {
	select {
	case event := <-w.cli.eventc:
		w.cli.clientConfig.eventHandler(event)
	default:
		return nil
	}
	return nil
}
func (w *clientEventWatcher) Destroy() {

}

func (w *clientEventWatcher) UserData() interface{} {
	return w
}
