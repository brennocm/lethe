package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Client is a synchronous JSON-RPC client; notifications go to OnNotify.
type Client struct {
	conn     net.Conn
	mu       sync.Mutex
	nextID   uint64
	r        *bufio.Reader
	OnNotify func(json.RawMessage)
}

// Dial connects to the daemon socket.
func Dial(path string, timeout time.Duration) (*Client, error) {
	c, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{conn: c, r: bufio.NewReaderSize(c, MaxMessage)}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Call sends method(params) with an optional proof and decodes the result into out.
func (c *Client) Call(method string, params any, auth *Auth, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	req := Request{JSONRPC: "2.0", ID: c.nextID, Method: method, Auth: auth}
	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return err
		}
		req.Params = raw
	}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(append(b, '\n')); err != nil {
		return err
	}
	for {
		line, err := c.r.ReadSlice('\n')
		if err != nil {
			return fmt.Errorf("ipc: read: %w", err)
		}
		var probe struct {
			ID     *uint64         `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(line, &probe); err != nil {
			return fmt.Errorf("ipc: bad reply: %w", err)
		}
		if probe.Method != "" && probe.ID == nil {
			if c.OnNotify != nil {
				c.OnNotify(probe.Params)
			}
			continue
		}
		var resp Response
		if err := json.Unmarshal(line, &resp); err != nil {
			return fmt.Errorf("ipc: bad reply: %w", err)
		}
		if resp.Error != nil {
			return resp.Error
		}
		if resp.ID == nil || *resp.ID != req.ID {
			return errors.New("ipc: reply for another request")
		}
		if out != nil {
			return json.Unmarshal(resp.Result, out)
		}
		return nil
	}
}

// ReadNotification blocks for the next server push (after events.subscribe).
func (c *Client) ReadNotification() (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	line, err := c.r.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	var n struct {
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(line, &n); err != nil {
		return nil, err
	}
	return n.Params, nil
}

// SetDeadline bounds the next operations.
func (c *Client) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// Prove asks for a challenge and returns the proof for method(params) under key.
func (c *Client) Prove(key []byte, method string, params any) (*Auth, error) {
	var ch struct {
		Nonce []byte `json:"nonce"`
	}
	if err := c.Call("auth.challenge", nil, nil, &ch); err != nil {
		return nil, err
	}
	raw := json.RawMessage(nil)
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	mac, err := MAC(key, ch.Nonce, method, raw)
	if err != nil {
		return nil, err
	}
	return &Auth{Nonce: ch.Nonce, MAC: mac}, nil
}
