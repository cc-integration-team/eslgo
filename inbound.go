/*
 * Copyright (c) 2020 Percipia
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Contributor(s):
 * Andrew Querol <aquerol@percipia.com>
 */
package eslgo

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/cc-integration-team/eslgo/command"
)

// InboundOptions - Used to dial a new inbound ESL connection to FreeSWITCH
type InboundOptions struct {
	Options                    // Generic common options to both Inbound and Outbound Conn
	Network      string        // The network type to use, should always be tcp, tcp4, tcp6.
	Password     string        // The password used to authenticate with FreeSWITCH. Usually ClueCon
	OnDisconnect func()        // An optional function to be called with the inbound connection gets disconnected
	AuthTimeout  time.Duration // How long to wait for authentication to complete
}

// DefaultOutboundOptions - The default options used for creating the inbound connection
var DefaultInboundOptions = InboundOptions{
	Options:     DefaultOptions,
	Network:     "tcp",
	Password:    "ClueCon",
	AuthTimeout: 5 * time.Second,
}

// Dial - Connects to FreeSWITCH ESL at the provided address and authenticates with the provided password. onDisconnect is called when the connection is closed either by us, FreeSWITCH, or network error
func Dial(address, password string, onDisconnect func()) (*Conn, error) {
	opts := DefaultInboundOptions
	opts.Password = password
	opts.OnDisconnect = onDisconnect
	return opts.Dial(address)
}

// DialContext - Like Dial but the TCP handshake and auth-challenge wait are both cancellable
// via ctx. ctx is also used as the base running context for the connection lifetime, so
// cancelling it will shut down the established connection's internal goroutines.
func DialContext(ctx context.Context, address, password string, onDisconnect func()) (*Conn, error) {
	opts := DefaultInboundOptions
	opts.Password = password
	opts.OnDisconnect = onDisconnect
	opts.Context = ctx
	return opts.DialContext(ctx, address)
}

// DialContextWithDialTimeout establishes an inbound ESL connection with separate timeout control:
//   - dialTimeout limits only the TCP+auth handshake phase.
//   - connCtx controls the connection lifetime after authentication succeeds.
//
// This is the recommended function when the caller needs a predictable upper bound on
// connection setup time (e.g. 30s) while keeping the live connection alive until connCtx
// is cancelled. A silent TCP SYN drop can otherwise block DialContext for ~75s (OS timeout).
//
// If dialTimeout is 0, no dial-phase timeout is applied (equivalent to DialContext(connCtx, ...)).
// dialCtx is derived as a child of connCtx, so cancelling connCtx always unblocks the dial too.
func DialContextWithDialTimeout(connCtx context.Context, dialTimeout time.Duration, address, password string, onDisconnect func()) (*Conn, error) {
	opts := DefaultInboundOptions
	opts.Password = password
	opts.OnDisconnect = onDisconnect
	opts.Context = connCtx // connection lifetime — independent of dial timeout

	if dialTimeout <= 0 {
		return opts.DialContext(connCtx, address)
	}

	// dialCtx is a child of connCtx: cancelling connCtx (e.g. DeregisterCore) also
	// cancels the dial phase immediately, so there is no goroutine leak.
	dialCtx, dialCancel := context.WithTimeout(connCtx, dialTimeout)
	defer dialCancel()
	return opts.DialContext(dialCtx, address)
}

// Dial - Connects to FreeSWITCH ESL on the address with the provided options. Returns the connection and any errors encountered
func (opts InboundOptions) Dial(address string) (*Conn, error) {
	c, err := net.Dial(opts.Network, address)
	if err != nil {
		return nil, err
	}
	connection := newConnection(c, false, opts.Options)

	// First auth
	<-connection.responseChannels[TypeAuthRequest]
	authCtx, cancel := context.WithTimeout(connection.runningContext, opts.AuthTimeout)
	err = connection.doAuth(authCtx, command.Auth{Password: opts.Password})
	cancel()
	if err != nil {
		// Try to gracefully disconnect, we have the wrong password.
		connection.ExitAndClose()
		if opts.OnDisconnect != nil {
			go opts.OnDisconnect()
		}
		return nil, err
	} else {
		connection.logger.Info("Successfully authenticated %s\n", connection.conn.RemoteAddr())
	}

	// Inbound only handlers
	go connection.authLoop(command.Auth{Password: opts.Password}, opts.AuthTimeout)
	go connection.disconnectLoop(opts.OnDisconnect)

	return connection, nil
}

// DialContext - Like Dial but cancellable: uses net.DialContext for TCP and a select on the
// auth-challenge channel so both blocking points respect ctx cancellation.
func (opts InboundOptions) DialContext(ctx context.Context, address string) (*Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, opts.Network, address)
	if err != nil {
		return nil, err
	}
	connection := newConnection(c, false, opts.Options)

	// Wait for FreeSWITCH auth challenge.
	// Two cancel paths:
	//   runningContext.Done() — connCtx cancelled (e.g. DeregisterCore), or receiveLoop error
	//   ctx.Done()           — dialCtx timeout elapsed (when dialCtx != connCtx)
	// When both are the same context the first ready case is picked; both return an error.
	select {
	case <-connection.responseChannels[TypeAuthRequest]:
	case <-connection.runningContext.Done():
		connection.ExitAndClose()
		return nil, connection.runningContext.Err()
	case <-ctx.Done():
		connection.ExitAndClose()
		return nil, ctx.Err()
	}

	authCtx, cancel := context.WithTimeout(connection.runningContext, opts.AuthTimeout)
	err = connection.doAuth(authCtx, command.Auth{Password: opts.Password})
	cancel()
	if err != nil {
		connection.ExitAndClose()
		if opts.OnDisconnect != nil {
			go opts.OnDisconnect()
		}
		return nil, err
	}
	connection.logger.Info("Successfully authenticated %s\n", connection.conn.RemoteAddr())

	go connection.authLoop(command.Auth{Password: opts.Password}, opts.AuthTimeout)
	go connection.disconnectLoop(opts.OnDisconnect)

	return connection, nil
}

func (c *Conn) disconnectLoop(onDisconnect func()) {
	select {
	case <-c.responseChannels[TypeDisconnect]:
		c.Close()
		if onDisconnect != nil {
			onDisconnect()
		}
		return
	case <-c.runningContext.Done():
		return
	}
}

func (c *Conn) authLoop(auth command.Auth, authTimeout time.Duration) {
	for {
		select {
		case <-c.responseChannels[TypeAuthRequest]:
			authCtx, cancel := context.WithTimeout(c.runningContext, authTimeout)
			err := c.doAuth(authCtx, auth)
			cancel()
			if err != nil {
				c.logger.Warn("Failed to auth %e\n", err)
				// Close the connection, we have the wrong password
				c.ExitAndClose()
				return
			} else {
				c.logger.Info("Successfully authenticated %s\n", c.conn.RemoteAddr())
			}
		case <-c.runningContext.Done():
			return
		}
	}
}

func (c *Conn) doAuth(ctx context.Context, auth command.Auth) error {
	response, err := c.SendCommand(ctx, auth)
	if err != nil {
		return err
	}
	if !response.IsOk() {
		return fmt.Errorf("failed to auth %#v", response)
	}
	return nil
}
