package zkmgr

import (
	"context"
	"log"
	"sync"
)

type InstancerCallBack func(ctx context.Context, parent string, new map[string]string) error
type InstancerErrCallBack func(ctx context.Context, err error)
type ChildCallBack func(ctx context.Context, parent, node string, data string) error

type ChildNodeInfo struct {
	Active   bool
	FullPath string
	Content  string
	Eventc   <-chan zkEvent
	Quitc    chan struct{}
}

// Instancer yield instances stored in a certain ZooKeeper path. Any kind of
// change in that path is watched and will update the subscribers.
type Instancer struct {
	client         Client
	path           string
	quitc          chan struct{}
	children       map[string]*ChildNodeInfo
	childrenMux    sync.RWMutex
	updateCallBack InstancerCallBack
	errCallBack    InstancerErrCallBack
	childCallBack  ChildCallBack
}

// NewInstancer returns a ZooKeeper Instancer. ZooKeeper will start watching
// the given path for changes and update the Instancer endpoints.
func NewInstancer(c Client, path string, cb InstancerCallBack, errcb InstancerErrCallBack, childcb ChildCallBack) (*Instancer, error) {
	s := &Instancer{
		client:         c,
		path:           path,
		quitc:          make(chan struct{}),
		updateCallBack: cb,
		errCallBack:    errcb,
		childCallBack:  childcb,
		children:       make(map[string]*ChildNodeInfo),
	}

	err := s.client.CreateParentNodes(s.path)
	if err != nil {
		return nil, err
	}

	instances, childrenc, eventc, err := s.client.GetWNodesAndEntries(s.path)
	if err != nil {
		log.Printf("[E]path(%s) failed to retrieve entries:%v\n", s.path, err)
		// other implementations continue here, but we exit because we don't know if eventc is valid
		return nil, err
	}
	log.Printf("[I]path(%s) len(instances)=%d\n", s.path, len(instances))
	if s.updateCallBack != nil {
		s.updateCallBack(context.Background(), s.path, instances)
	}
	for k, v := range instances {
		info := &ChildNodeInfo{
			Active:   true,
			FullPath: k,
			Content:  v,
			Eventc:   childrenc[k],
			Quitc:    make(chan struct{}),
		}
		s.childrenMux.Lock()
		s.children[k] = info
		s.childrenMux.Unlock()
		go s.watchChild(info)
	}

	go s.loop(eventc)

	return s, nil
}

func (s *Instancer) watchChild(child *ChildNodeInfo) {
	var (
		data string
		err  error
	)
	defer func() {
		s.childrenMux.Lock()
		delete(s.children, child.FullPath)
		s.childrenMux.Unlock()
	}()
	for {
		select {
		case ev := <-child.Eventc:
			log.Printf("[I]child(%s) eventtype(%s) server(%s) state(%s) err(%v)\n", child.FullPath, ev.Type.String(), ev.Server, ev.State.String(), ev.Err)
			// We received a path update notification. Call GetEntries to
			// retrieve child node data, and set a new watch, as ZK watches are
			// one-time triggers.
			if ev.Type == zkEventNodeDeleted {
				close(child.Quitc)
				return
			}
			data, child.Eventc, err = s.client.GetWEntry(child.FullPath)
			if err != nil {
				log.Printf("[E]child(%s) failed to retrieve entry:%v\n", child.FullPath, err)
				if s.errCallBack != nil {
					s.errCallBack(context.Background(), err)
				}
				continue
			}
			log.Printf("[I]child(%s) data=%s\n", child.FullPath, data)
			if s.childCallBack != nil {
				s.childCallBack(context.Background(), s.path, child.FullPath, data)
			}

		case <-child.Quitc:
			return
		}
	}
}

func (s *Instancer) loop(eventc <-chan zkEvent) {
	var (
		instances      map[string]string
		childreneventc map[string]<-chan zkEvent
		err            error
	)
	for {
		select {
		case ev := <-eventc:
			log.Printf("[I]Instancer eventtype(%s) server(%s) state(%s) err(%v)\n", ev.Type.String(), ev.Server, ev.State.String(), ev.Err)
			// We received a path update notification. Call GetEntries to
			// retrieve child node data, and set a new watch, as ZK watches are
			// one-time triggers.
			instances, childreneventc, eventc, err = s.client.GetWNodesAndEntries(s.path)
			if err != nil {
				log.Printf("[E]path(%s) failed to retrieve entries:%v\n", s.path, err)
				if s.errCallBack != nil {
					s.errCallBack(context.Background(), err)
				}
				continue
			}
			if s.updateCallBack != nil {
				s.updateCallBack(context.Background(), s.path, instances)
			}
			s.childrenMux.Lock()
			for _, v := range s.children {
				v.Active = false
			}

			for k, v := range instances {
				if _, ok := s.children[k]; !ok {
					info := &ChildNodeInfo{
						Active:   true,
						FullPath: k,
						Content:  v,
						Eventc:   childreneventc[k],
						Quitc:    make(chan struct{}),
					}
					s.children[k] = info
					go s.watchChild(info)
				}
			}

			for k, v := range s.children {
				if v.Active == false {
					v.Quitc <- struct{}{}
					close(v.Quitc)
					delete(s.children, k)
				}
			}
			s.childrenMux.Unlock()
		case <-s.quitc:
			return
		}
	}
}

// Stop terminates the Instancer.
func (s *Instancer) Stop() {
	close(s.quitc)
}
