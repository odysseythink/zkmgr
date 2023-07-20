package zkmgr

import (
	"errors"
	"fmt"
)

const (
	protocolVersion = 0

	DefaultPort = 2181
)

const (
	opNotify          = 0
	opCreate          = 1
	opDelete          = 2
	opExists          = 3
	opGetData         = 4
	opSetData         = 5
	opGetAcl          = 6
	opSetAcl          = 7
	opGetChildren     = 8
	opSync            = 9
	opPing            = 11
	opGetChildren2    = 12
	opCheck           = 13
	opMulti           = 14
	opReconfig        = 16
	opCreateContainer = 19
	opCreateTTL       = 21
	opClose           = -11
	opSetAuth         = 100
	opSetWatches      = 101
	opError           = -1
	// Not in protocol, used internally
	opWatcherEvent = -2
)

const (
	zkEventNodeCreated         EventType = 1
	zkEventNodeDeleted         EventType = 2
	zkEventNodeDataChanged     EventType = 3
	zkEventNodeChildrenChanged EventType = 4

	zkEventSession     EventType = -1
	zkEventNotWatching EventType = -2
)

var (
	eventNames = map[EventType]string{
		zkEventNodeCreated:         "EventNodeCreated",
		zkEventNodeDeleted:         "EventNodeDeleted",
		zkEventNodeDataChanged:     "EventNodeDataChanged",
		zkEventNodeChildrenChanged: "EventNodeChildrenChanged",
		zkEventSession:             "EventSession",
		zkEventNotWatching:         "EventNotWatching",
	}
)

const (
	zkStateUnknown           State = -1
	zkStateDisconnected      State = 0
	zkStateConnecting        State = 1
	zkStateAuthFailed        State = 4
	zkStateConnectedReadOnly State = 5
	zkStateSaslAuthenticated State = 6
	zkStateExpired           State = -112

	zkStateConnected  = State(100)
	zkStateHasSession = State(101)
)

const (
	zkFlagEphemeral = 1
	zkFlagSequence  = 2
	zkFlagTTL       = 4
)

var (
	stateNames = map[State]string{
		zkStateUnknown:           "StateUnknown",
		zkStateDisconnected:      "StateDisconnected",
		zkStateConnectedReadOnly: "StateConnectedReadOnly",
		zkStateSaslAuthenticated: "StateSaslAuthenticated",
		zkStateExpired:           "StateExpired",
		zkStateAuthFailed:        "StateAuthFailed",
		zkStateConnecting:        "StateConnecting",
		zkStateConnected:         "StateConnected",
		zkStateHasSession:        "StateHasSession",
	}
)

type State int32

func (s State) String() string {
	if name := stateNames[s]; name != "" {
		return name
	}
	return "Unknown"
}

type ErrCode int32

var (
	zkErrConnectionClosed        = errors.New("zk: connection closed")
	zkErrUnknown                 = errors.New("zk: unknown error")
	zkErrAPIError                = errors.New("zk: api error")
	zkErrNoNode                  = errors.New("zk: node does not exist")
	zkErrNoAuth                  = errors.New("zk: not authenticated")
	zkErrBadVersion              = errors.New("zk: version conflict")
	zkErrNoChildrenForEphemerals = errors.New("zk: ephemeral nodes may not have children")
	zkErrNodeExists              = errors.New("zk: node already exists")
	zkErrNotEmpty                = errors.New("zk: node has children")
	zkErrSessionExpired          = errors.New("zk: session has been expired by the server")
	zkErrInvalidACL              = errors.New("zk: invalid ACL specified")
	zkErrInvalidFlags            = errors.New("zk: invalid flags specified")
	zkErrAuthFailed              = errors.New("zk: client authentication failed")
	zkErrClosing                 = errors.New("zk: zookeeper is closing")
	zkErrNothing                 = errors.New("zk: no server responsees to process")
	zkErrSessionMoved            = errors.New("zk: session moved to another server, so operation is ignored")
	zkErrReconfigDisabled        = errors.New("attempts to perform a reconfiguration operation when reconfiguration feature is disabled")
	zkErrBadArguments            = errors.New("invalid arguments")
	// ErrInvalidCallback         = errors.New("zk: invalid callback specified")

	errCodeToError = map[ErrCode]error{
		0:                          nil,
		errAPIError:                zkErrAPIError,
		errNoNode:                  zkErrNoNode,
		errNoAuth:                  zkErrNoAuth,
		errBadVersion:              zkErrBadVersion,
		errNoChildrenForEphemerals: zkErrNoChildrenForEphemerals,
		errNodeExists:              zkErrNodeExists,
		errNotEmpty:                zkErrNotEmpty,
		errSessionExpired:          zkErrSessionExpired,
		// errInvalidCallback:         zkErrInvalidCallback,
		errInvalidAcl:        zkErrInvalidACL,
		errAuthFailed:        zkErrAuthFailed,
		errClosing:           zkErrClosing,
		errNothing:           zkErrNothing,
		errSessionMoved:      zkErrSessionMoved,
		errZReconfigDisabled: zkErrReconfigDisabled,
		errBadArguments:      zkErrBadArguments,
	}
)

func (e ErrCode) toError() error {
	if err, ok := errCodeToError[e]; ok {
		return err
	}
	return fmt.Errorf("unknown error: %v", e)
}

const (
	errOk = 0
	// System and server-side errors
	errSystemError          = -1
	errRuntimeInconsistency = -2
	errDataInconsistency    = -3
	errConnectionLoss       = -4
	errMarshallingError     = -5
	errUnimplemented        = -6
	errOperationTimeout     = -7
	errBadArguments         = -8
	errInvalidState         = -9
	// API errors
	errAPIError                ErrCode = -100
	errNoNode                  ErrCode = -101 // *
	errNoAuth                  ErrCode = -102
	errBadVersion              ErrCode = -103 // *
	errNoChildrenForEphemerals ErrCode = -108
	errNodeExists              ErrCode = -110 // *
	errNotEmpty                ErrCode = -111
	errSessionExpired          ErrCode = -112
	errInvalidCallback         ErrCode = -113
	errInvalidAcl              ErrCode = -114
	errAuthFailed              ErrCode = -115
	errClosing                 ErrCode = -116
	errNothing                 ErrCode = -117
	errSessionMoved            ErrCode = -118
	// Attempts to perform a reconfiguration operation when reconfiguration feature is disabled
	errZReconfigDisabled ErrCode = -123
)

// Constants for ACL permissions
const (
	zkPermRead = 1 << iota
	zkPermWrite
	zkPermCreate
	zkPermDelete
	zkPermAdmin
	zkPermAll = 0x1f
)

var (
	emptyPassword = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	opNames       = map[int32]string{
		opNotify:          "notify",
		opCreate:          "create",
		opCreateContainer: "createContainer",
		opCreateTTL:       "createTTL",
		opDelete:          "delete",
		opExists:          "exists",
		opGetData:         "getData",
		opSetData:         "setData",
		opGetAcl:          "getACL",
		opSetAcl:          "setACL",
		opGetChildren:     "getChildren",
		opSync:            "sync",
		opPing:            "ping",
		opGetChildren2:    "getChildren2",
		opCheck:           "check",
		opMulti:           "multi",
		opReconfig:        "reconfig",
		opClose:           "close",
		opSetAuth:         "setAuth",
		opSetWatches:      "setWatches",

		opWatcherEvent: "watcherEvent",
	}
)

type EventType int32

func (t EventType) String() string {
	if name := eventNames[t]; name != "" {
		return name
	}
	return "Unknown"
}

// Mode is used to build custom server modes (leader|follower|standalone).
type Mode uint8

func (m Mode) String() string {
	if name := modeNames[m]; name != "" {
		return name
	}
	return "unknown"
}

const (
	ModeUnknown    Mode = iota
	ModeLeader     Mode = iota
	ModeFollower   Mode = iota
	ModeStandalone Mode = iota
)

var (
	modeNames = map[Mode]string{
		ModeLeader:     "leader",
		ModeFollower:   "follower",
		ModeStandalone: "standalone",
	}
)
