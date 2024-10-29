// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clientserver

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/field"
	"github.com/falcosecurity/event-generator/pkg/test/resource"
)

// clientServer implements a clientServer resource.
type clientServer struct {
	logger logr.Logger
	// resourceName is the resource name.
	resourceName string
	// l4Proto is the transport protocol used by the client and server.
	l4Proto string
	// address is an address in the form accepted by net.SplitHostPort or empty, in case of l4Proto equal to "unix".
	address string
	// fields defines the information exposed by clientServer for binding.
	fields struct {
		// Client defines the exposed client information.
		Client struct {
			FD int `field_type:"fd"`
		}
		// Server defines the exposed server information.
		Server struct {
			FD int `field_type:"fd"`
		}
	}
	// createdLinkName stores the name of the created link. If no link is created, it is empty.
	createdLinkName string
	// createdUnixSockFilePath is the file path of the created unix socket file or empty, in case of l4Proto different
	// from "unix".
	createdUnixSockFilePath string
	// openFDs is the set of open file descriptors. This contains both client and server FDs as well as any other FD
	// used by the resource.
	openFDs map[int]struct{}
	// waitGroup allows to wait for client and server termination.
	waitGroup sync.WaitGroup
	// shutdownCh allows to signal client and server termination.
	shutdownCh chan struct{}
}

// Verify that clientServer implements resource.Resource interface.
var _ resource.Resource = (*clientServer)(nil)

// New creates a new clientServer resource.
func New(logger logr.Logger, resourceName, l4Proto, address string) resource.Resource {
	cs := &clientServer{
		logger:       logger,
		resourceName: resourceName,
		l4Proto:      l4Proto,
		address:      address,
		waitGroup:    sync.WaitGroup{},
		openFDs:      make(map[int]struct{}),
	}
	cs.fields.Client.FD = -1
	cs.fields.Server.FD = -1
	return cs
}

func (cs *clientServer) Name() string {
	return cs.resourceName
}

var errUnixSockAddrMustBeEmpty = fmt.Errorf("address must be empty for unix sockets")

func (cs *clientServer) Create(ctx context.Context) error {
	var socketDomain, socketType int
	isUnix := false
	useIPv4 := true
	switch l4Proto := cs.l4Proto; l4Proto {
	case "tcp4":
		socketDomain, socketType = unix.AF_INET, unix.SOCK_STREAM
	case "tcp6":
		socketDomain, socketType = unix.AF_INET6, unix.SOCK_STREAM
		useIPv4 = false
	case "udp4":
		socketDomain, socketType = unix.AF_INET, unix.SOCK_DGRAM
	case "udp6":
		socketDomain, socketType = unix.AF_INET6, unix.SOCK_DGRAM
		useIPv4 = false
	case "unix":
		socketDomain, socketType = unix.AF_UNIX, unix.SOCK_STREAM
		isUnix = true
	default:
		return fmt.Errorf("unsupported l4 proto %q", l4Proto)
	}

	address := cs.address
	var sockaddr unix.Sockaddr
	if !isUnix {
		ipAddr, port, err := splitIPPort(address)
		if err != nil {
			return fmt.Errorf("error parsing IP and port from %q: %w", address, err)
		}

		isIPv4Address := strings.ContainsRune(address, '.')
		if useIPv4 != isIPv4Address {
			return fmt.Errorf("protocol and address must must be both IPv4 or IPv6")
		}

		linkName, err := ensureLinkWithAddress(ipAddr, isIPv4Address)
		if err != nil {
			return fmt.Errorf("error ensuring link with address: %w", err)
		}
		cs.createdLinkName = linkName

		sockaddr = netSockaddr(ipAddr, port, isIPv4Address)
	} else {
		if address != "" {
			return errUnixSockAddrMustBeEmpty
		}

		unixSockFilePath := newUnixSockFilePath()
		cs.createdUnixSockFilePath = unixSockFilePath
		cs.logger.V(1).Info("Evaluated unix socket file path", "path", unixSockFilePath)
		sockaddr = unixSockaddr(unixSockFilePath)
	}

	cs.shutdownCh = make(chan struct{})
	if err := cs.spawnServer(socketDomain, socketType, 0, sockaddr); err != nil {
		_ = cs.Destroy(ctx)
		return fmt.Errorf("error spawning server: %w", err)
	}

	if err := cs.spawnClient(socketDomain, socketType, 0, sockaddr); err != nil {
		_ = cs.Destroy(ctx)
		return fmt.Errorf("error spawning client: %w", err)
	}

	return nil
}

var (
	errUnparsableIPAddr = fmt.Errorf("unparsable IP address")
	errPortOutOfRange   = fmt.Errorf("port number must be in range (0, 655535]")
)

// splitIPPort splits a network address of the form "ip:port", "ip%zone:port", "[ip]:port" or "[ip%zone]:port"
// into ip and port. A literal IPv6 address must be enclosed in square brackets, as in "[::1]:80".
func splitIPPort(address string) (net.IP, int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, 0, fmt.Errorf("error splitting host and port parts: %w", err)
	}

	ipAddr := net.ParseIP(host)
	if ipAddr == nil {
		return nil, 0, errUnparsableIPAddr
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return nil, 0, fmt.Errorf("error parsing port part: %w", err)
	}

	if portNum <= 0 || portNum > 65535 {
		return nil, 0, errPortOutOfRange
	}

	return ipAddr, portNum, nil
}

// ensureLinkWithAddress ensures the existence on the system of a link with the provided address. If the link already
// exists, the function does nothing; if the link doesn't exist, it creates a new link and configures the provided
// address on it. In a new link is created, the function returns its name.
func ensureLinkWithAddress(ipAddr net.IP, isIPv4Address bool) (string, error) {
	// Retrieve the first link with the provided address.
	var family int
	if isIPv4Address {
		family = netlink.FAMILY_V4
	} else {
		family = netlink.FAMILY_V6
	}
	link, err := linkByAddress(ipAddr, family)
	if err != nil {
		return "", fmt.Errorf("error retrieving link associated to address %v", ipAddr)
	}

	if link != nil {
		return "", nil
	}

	// No link with the provided address, so create it.
	return createLinkWithAddress(ipAddr, isIPv4Address)
}

// linkByAddress returns the first link on the system with the provided address. If the address is not found, nil is
// returned.
func linkByAddress(ipAddr net.IP, family int) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("error retrieving link list: %w", err)
	}

	for _, link := range links {
		addrList, err := netlink.AddrList(link, family)
		if err != nil {
			return nil, fmt.Errorf("error retrieving link %q address list: %w", link.Attrs().Name, err)
		}

		for _, addr := range addrList {
			if !addr.IP.Equal(ipAddr) {
				continue
			}
			return link, nil
		}
	}

	return nil, nil
}

const (
	// linkNamePrefix is the prefix used for new links.
	linkNamePrefix = "du"
	// unixSocketNamePathPrefix is the path under which new unix socket files will be stored.
	unixSocketNamePathPrefix = "/tmp/clientserver"
)

var (
	ipv4Mask = net.CIDRMask(32, 32)
	ipv6Mask = net.CIDRMask(128, 128)
)

// createLinkWithAddress creates a link on the system and configures the provided address on it, with a prefix length
// of 32 (for IPv4) or 128 (for IPv6). It returns the name of the created link.
func createLinkWithAddress(ipAddr net.IP, isIPv4Address bool) (linkName string, err error) {
	name := linkNamePrefix + randSeq(4)
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(link); err != nil {
		return "", fmt.Errorf("error creating link %q: %w", name, err)
	}

	// If any error occur after the link creation, delete the link.
	defer func() {
		if err == nil {
			return
		}
		if e := netlink.LinkDel(link); e != nil {
			err = fmt.Errorf("%w; error deleting link %q: %w", err, name, e)
		}
	}()

	if err := netlink.LinkSetUp(link); err != nil {
		return "", fmt.Errorf("error setting link %q up: %w", name, err)
	}

	var mask net.IPMask
	if isIPv4Address {
		mask = ipv4Mask
	} else {
		mask = ipv6Mask
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{
		IP:   ipAddr,
		Mask: mask,
	}}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return "", fmt.Errorf("error adding address %q to link %q: %w", ipAddr, name, err)
	}

	return name, nil
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// randSeq generates a random sequence of length n.
func randSeq(n int) string {
	b := make([]rune, n)
	lettersLen := len(letters)
	for i := range b {
		letterIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(lettersLen)))
		b[i] = letters[letterIndex.Int64()]
	}
	return string(b)
}

// netSockaddr returns the unix.Sockaddr associated to the provided IP address and port.
func netSockaddr(ipAddr net.IP, port int, isIPv4Address bool) unix.Sockaddr {
	if isIPv4Address {
		return &unix.SockaddrInet4{Port: port, Addr: [4]byte(ipAddr[12:])}
	}

	return &unix.SockaddrInet6{Port: port, Addr: [16]byte(ipAddr)}
}

// newUnixSockFilePath creates a new random path to store a unix socket file.
func newUnixSockFilePath() string {
	return unixSocketNamePathPrefix + randSeq(4) + ".sock"
}

// unixSockaddr returns a unix.Sockaddr associated to the provided unix socket file path.
func unixSockaddr(unixSockFilePath string) unix.Sockaddr {
	return &unix.SockaddrUnix{Name: unixSockFilePath}
}

// spawnServer creates a new server socket and configures it to accept incoming clients. The socket is bound to the
// address configured in the provided sockaddr.
func (cs *clientServer) spawnServer(socketDomain, socketType, socketProtocol int, sockaddr unix.Sockaddr) error {
	serverSocketFD, err := unix.Socket(socketDomain, socketType|unix.SOCK_NONBLOCK, socketProtocol)
	if err != nil {
		return fmt.Errorf("error creating server socket: %w", err)
	}

	cs.fields.Server.FD = serverSocketFD
	cs.openFDs[serverSocketFD] = struct{}{}
	cs.logger.V(1).Info("Registered server socket FD", "fd", serverSocketFD)

	if err := unix.Bind(serverSocketFD, sockaddr); err != nil {
		// Failing the binding for a unix socket means that we were not able to create the unix socket file, so set the
		// path to be empty in order to avoid unneeded unlink calls.
		cs.createdUnixSockFilePath = ""
		return fmt.Errorf("error binding server socket: %w", err)
	}

	if socketType == unix.SOCK_DGRAM {
		return nil
	}

	if err := unix.Listen(serverSocketFD, unix.SOMAXCONN); err != nil {
		return fmt.Errorf("error putting server socket in listening state: %w", err)
	}

	return cs.manageStreamServer(serverSocketFD)
}

// manageStreamServer sets up the infrastructure to handle incoming connections and closed peers.
func (cs *clientServer) manageStreamServer(serverFD int) error {
	// Create epoll instance to wait for asynchronous server socket events.
	epollFD, err := cs.createEpollFD()
	if err != nil {
		return fmt.Errorf("error creating epoll instance: %w", err)
	}

	// Create event FD to unblock epoll instance waiting upon the reception of shutdown signal.
	eventFD, err := cs.createEventFD()
	if err != nil {
		return fmt.Errorf("error creating event FD: %w", err)
	}

	// Register event and socket FDs into epoll instance.
	for _, epollEvent := range []*unix.EpollEvent{
		//nolint:gosec // Disable G115
		{Events: unix.EPOLLIN | unix.EPOLLET, Fd: int32(eventFD)},
		//nolint:gosec // Disable G115
		{Events: unix.EPOLLRDHUP | unix.EPOLLHUP, Fd: int32(serverFD)},
	} {
		if err = unix.EpollCtl(epollFD, unix.EPOLL_CTL_ADD, int(epollEvent.Fd), epollEvent); err != nil {
			return fmt.Errorf("error registering FD %d to epoll instance: %w", epollEvent.Fd, err)
		}
	}

	// Creating a goroutine to handle incoming/closed connection connections.
	cs.waitGroup.Add(1)
	go func() {
		defer cs.waitGroup.Done()
		var epollEvents [32]unix.EpollEvent
		for {
			eventsNum, err := unix.EpollWait(epollFD, epollEvents[:], -1)
			if err != nil {
				cs.logger.Error(err, "Error waiting on epoll instance")
				return
			}

			if err := cs.handleStreamServerEpollEvents(epollEvents[:eventsNum], epollFD, eventFD,
				serverFD); err != nil {
				return
			}
		}
	}()

	return nil
}

// createEpollFD creates a new epoll FD and accounts for it in clientServer.openFDs. It returns the created FD.
func (cs *clientServer) createEpollFD() (int, error) {
	epollFD, err := unix.EpollCreate1(0)
	if err != nil {
		return 0, err
	}

	cs.openFDs[epollFD] = struct{}{}
	cs.logger.V(1).Info("Registered open epoll FD", "fd", epollFD)
	return epollFD, nil
}

// createEventFD creates a new event FD and accounts for it in clientServer.openFDs. If clientServer.shutdownCh is
// closed, a value is added to the event FD counter and it becomes readable. It returns the created FD.
func (cs *clientServer) createEventFD() (int, error) {
	eventFD, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return 0, err
	}

	cs.openFDs[eventFD] = struct{}{}
	cs.logger.V(1).Info("Registered open event FD", "fd", eventFD)
	cs.waitAndForwardShutdownSignal(eventFD)
	return eventFD, nil
}

// waitAndForwardShutdownSignal waits for a shutdown signal to be sent on clientServer.shutdownCh and increments the
// value of the counter associated with the provided eventFD.
func (cs *clientServer) waitAndForwardShutdownSignal(eventFD int) {
	go func() {
		<-cs.shutdownCh
		b := [8]byte{0, 0, 0, 0, 0, 0, 0, 1}
		if _, err := unix.Write(eventFD, b[:]); err != nil {
			cs.logger.Error(err, "Error incrementing event FD counter")
		}
	}()
}

// handleStreamServerEpollEvents handles the provided epoll events based on their associated FDs and event types.
func (cs *clientServer) handleStreamServerEpollEvents(epollEvents []unix.EpollEvent, epollFD, eventFD,
	serverFD int) error {
	for i := 0; i < len(epollEvents); i++ {
		epollEvent := &epollEvents[i]
		switch fd := int(epollEvent.Fd); fd {
		case eventFD:
			return fmt.Errorf("resource destroyed")
		case serverFD:
			connFD, _, e := unix.Accept(serverFD)
			if e != nil {
				cs.logger.Error(e, "Error accepting connection from server")
				continue
			}

			cs.registerConnFD(epollFD, connFD)
		default:
			if epollEvent.Events&(unix.EPOLLRDHUP|unix.EPOLLHUP) != 0 {
				cs.unregisterConnFD(epollFD, fd)
			}
		}
	}
	return nil
}

// registerConnFD registers the provided connection FD to the provided epoll instance and accounts for it in
// clientServer.openFDs. If the operation cannot succeed the connection is closed.
func (cs *clientServer) registerConnFD(epollFD, connFD int) {
	//nolint:gosec // Disable G115
	ePollEvent := &unix.EpollEvent{Events: uint32(unix.EPOLLRDHUP | unix.EPOLLHUP), Fd: int32(connFD)}
	if err := unix.EpollCtl(epollFD, unix.EPOLL_CTL_ADD, int(ePollEvent.Fd), ePollEvent); err != nil {
		cs.logger.Error(err, "Error registering connection FD to epoll instance", "fd", connFD)
		if err := unix.Close(connFD); err != nil {
			cs.logger.Error(err, "Error closing connection FD after error occurred", "fd", connFD)
		}
		return
	}

	cs.openFDs[connFD] = struct{}{}
	cs.logger.V(1).Info("Registered connection FD", "fd", connFD)
}

// unregisterConnFD unregisters the provided connection FD from the provided epoll instance and accounts for it in
// clientServer.openFDs.
func (cs *clientServer) unregisterConnFD(epollFD, connFD int) {
	if err := unix.EpollCtl(epollFD, unix.EPOLL_CTL_DEL, connFD, nil); err != nil {
		cs.logger.Error(err, "Error unregistering connection FD from epoll instance", "fd", connFD)
	}
	if err := unix.Close(connFD); err != nil {
		cs.logger.Error(err, "Error closing connection FD", "fd", connFD)
	}
	delete(cs.openFDs, connFD)
	cs.logger.V(1).Info("Unregistered connection FD", "fd", connFD)
}

// spawnClient creates a new client socket. If the socket is a stream socket, a connection is established with the
// server at the provided serverSockaddr.
func (cs *clientServer) spawnClient(socketDomain, socketType, socketProtocol int, serverSockaddr unix.Sockaddr) error {
	clientSocketFD, err := unix.Socket(socketDomain, socketType|unix.SOCK_NONBLOCK, socketProtocol)
	if err != nil {
		return fmt.Errorf("error creating client socket: %w", err)
	}

	cs.fields.Client.FD = clientSocketFD
	cs.openFDs[clientSocketFD] = struct{}{}
	cs.logger.V(1).Info("Registered client socket FD", "fd", clientSocketFD)

	if socketType == unix.SOCK_DGRAM {
		return nil
	}

	return cs.manageStreamClient(clientSocketFD, serverSockaddr)
}

// manageStreamClient establishes and handles the termination of the connection of the client with the server at the
// provided serverSockaddr.
func (cs *clientServer) manageStreamClient(clientFD int, serverSockaddr unix.Sockaddr) error {
	// Create epoll instance to wait for asynchronous client socket events.
	epollFD, err := cs.createEpollFD()
	if err != nil {
		return fmt.Errorf("error creating epoll instance: %w", err)
	}

	// Create event FD to unblock epoll instance waiting upon the reception of shutdown signal.
	eventFD, err := cs.createEventFD()
	if err != nil {
		return fmt.Errorf("error creating event FD: %w", err)
	}

	// Register event and socket FDs into epoll instance.
	for _, epollEvent := range []*unix.EpollEvent{
		//nolint:gosec // Disable G115
		{Events: unix.EPOLLIN | unix.EPOLLET, Fd: int32(eventFD)},
		//nolint:gosec // Disable G115
		{Events: unix.EPOLLOUT | unix.EPOLLHUP | unix.EPOLLRDHUP, Fd: int32(clientFD)},
	} {
		if err = unix.EpollCtl(epollFD, unix.EPOLL_CTL_ADD, int(epollEvent.Fd), epollEvent); err != nil {
			return fmt.Errorf("error registering FD %d to epoll instance: %w", epollEvent.Fd, err)
		}
	}

	// Wait until connection with the server is established.
	if err := unix.Connect(clientFD, serverSockaddr); err != nil {
		if !errors.Is(err, unix.EINPROGRESS) {
			return fmt.Errorf("error connecting to server: %w", err)
		}

		if err := cs.waitForConnection(epollFD, eventFD, clientFD); err != nil {
			return fmt.Errorf("error waiting for client connection: %w", err)
		}
	}
	cs.logger.V(1).Info("Client connected")

	return nil
}

// waitForConnection waits until a connection is established. The event is recognized by waiting for a connection event
// to be signaled, on the provided epoll instance, for the provided clientFD. An event on the provided eventFD triggers
// the termination of the wait.
func (cs *clientServer) waitForConnection(epollFD, eventFD, clientFD int) error {
	var epollEvents [32]unix.EpollEvent
	connected := false
	for !connected {
		eventsNum, err := unix.EpollWait(epollFD, epollEvents[:], -1)
		if err != nil {
			return fmt.Errorf("error waiting on epoll instance: %w", err)
		}

		if connected, err = cs.checkConnStatus(epollEvents[:eventsNum], eventFD, clientFD); err != nil {
			return fmt.Errorf("error checking connection status: %w", err)
		}
	}
	return nil
}

// checkConnStatus inspects the provided epoll events to verify if the connection has been established with the server.
// An event on the provided eventFD triggers the termination of the inspection. The function returns true if the
// connection is established, false otherwise.
func (cs *clientServer) checkConnStatus(epollEvents []unix.EpollEvent, eventFD, clientFD int) (bool, error) {
	connected := false
	for i := 0; i < len(epollEvents); i++ {
		epollEvent := &epollEvents[i]
		switch fd := int(epollEvent.Fd); fd {
		case eventFD:
			return false, fmt.Errorf("resource destroyed")
		case clientFD:
			if epollEvent.Events&(unix.EPOLLRDHUP|unix.EPOLLHUP) != 0 {
				return false, fmt.Errorf("received server disconnection event")
			}

			result, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if err != nil {
				return false, fmt.Errorf("error getting client socket options: %w", err)
			}

			if result != 0 {
				return false, fmt.Errorf("error connecting to server: %w", unix.Errno(result))
			}

			connected = true
		}
	}

	return connected, nil
}

func (cs *clientServer) Destroy(_ context.Context) error {
	close(cs.shutdownCh)

	cs.waitGroup.Wait()
	cs.shutdownCh = nil

	// Close any open FD.
	for fd := range cs.openFDs {
		if err := unix.Close(fd); err != nil {
			cs.logger.Error(err, "Error closing FD", "fd", fd)
		}
		cs.logger.V(1).Info("Closed FD", "fd", fd)
	}
	cs.openFDs = make(map[int]struct{})
	cs.fields.Client.FD = -1
	cs.fields.Server.FD = -1

	// Delete the link, if it was created.
	if linkName := cs.createdLinkName; linkName != "" {
		link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: linkName}}
		if err := netlink.LinkDel(link); err != nil {
			cs.logger.Error(err, "Error deleting link", "name", linkName)
		}
		cs.createdLinkName = ""
	}

	if cs.createdUnixSockFilePath != "" {
		if err := os.Remove(cs.createdUnixSockFilePath); err != nil {
			cs.logger.Error(err, "Error removing unix socket file")
		}
		cs.createdUnixSockFilePath = ""
	}

	return nil
}

func (cs *clientServer) Field(name string) (*field.Field, error) {
	fieldContainer := reflect.ValueOf(cs.fields)
	return field.ByName(name, fieldContainer)
}
