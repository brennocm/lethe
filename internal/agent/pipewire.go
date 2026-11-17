package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lethe/internal/checks"
)

// A minimal client of the PipeWire native protocol (version 3): it says hello, asks for the
// registry, waits for the sync to complete and counts the nodes that mean capture (HOST-002) or
// screen sharing (HOST-003). It never creates or links objects.

const (
	pwCoreID     = 0
	pwClientID   = 1
	pwRegistryID = 2

	pwCoreHello       = 1
	pwCoreSync        = 2
	pwCorePong        = 3
	pwCoreGetRegistry = 5
	pwClientUpdate    = 2

	pwEvCoreDone   = 1
	pwEvCorePing   = 2
	pwEvCoreError  = 3
	pwEvGlobal     = 0
	pwVersion      = 3
	pwMaxMessage   = 1 << 20
	pwSyncSeq      = 0x4c45 // arbitrary
	podTypeInt     = 4
	podTypeLong    = 5
	podTypeString  = 8
	podTypeStruct  = 14
	podTypeNone    = 1
	podTypeID      = 3
	podTypeBool    = 2
	podMaxDepth    = 8
	pwReadDeadline = 3 * time.Second
)

// pwSocket finds the PipeWire socket of the session.
func pwSocket(getenv func(string) string) string {
	name := getenv("PIPEWIRE_REMOTE")
	if name == "" {
		name = "pipewire-0"
	}
	if filepath.IsAbs(name) {
		return name
	}
	dir := getenv("PIPEWIRE_RUNTIME_DIR")
	if dir == "" {
		dir = getenv("XDG_RUNTIME_DIR")
	}
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, name)
}

// pod encoding

func pad8(n int) int { return (n + 7) &^ 7 }

func podInt(v int32) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:], 4)
	binary.LittleEndian.PutUint32(b[4:], podTypeInt)
	binary.LittleEndian.PutUint32(b[8:], uint32(v))
	return b
}

func podString(s string) []byte {
	n := len(s) + 1
	b := make([]byte, 8+pad8(n))
	binary.LittleEndian.PutUint32(b[0:], uint32(n))
	binary.LittleEndian.PutUint32(b[4:], podTypeString)
	copy(b[8:], s)
	return b
}

func podStruct(fields ...[]byte) []byte {
	var body []byte
	for _, f := range fields {
		body = append(body, f...)
	}
	b := make([]byte, 8, 8+len(body))
	binary.LittleEndian.PutUint32(b[0:], uint32(len(body)))
	binary.LittleEndian.PutUint32(b[4:], podTypeStruct)
	return append(b, body...)
}

func podDict(kv ...string) []byte {
	fields := [][]byte{podInt(int32(len(kv) / 2))}
	for _, s := range kv {
		fields = append(fields, podString(s))
	}
	return podStruct(fields...)
}

func pwMessage(id uint32, opcode uint8, seq uint32, payload []byte) []byte {
	h := make([]byte, 16, 16+len(payload))
	binary.LittleEndian.PutUint32(h[0:], id)
	binary.LittleEndian.PutUint32(h[4:], uint32(opcode)<<24|uint32(len(payload))&0xffffff)
	binary.LittleEndian.PutUint32(h[8:], seq)
	return append(h, payload...)
}

// pod decoding

// podValue is a decoded pod: Int/Long in Num, String in Str, Struct fields in Fields.
type podValue struct {
	Type   uint32
	Num    int64
	Str    string
	Fields []podValue
}

var errPod = errors.New("pipewire: malformed pod")

// parsePod decodes one pod at the start of b and returns it with the bytes it used (padded).
func parsePod(b []byte, depth int) (podValue, int, error) {
	if len(b) < 8 || depth > podMaxDepth {
		return podValue{}, 0, errPod
	}
	size := int(binary.LittleEndian.Uint32(b[0:]))
	typ := binary.LittleEndian.Uint32(b[4:])
	if size < 0 || size > len(b)-8 {
		return podValue{}, 0, errPod
	}
	body := b[8 : 8+size]
	used := 8 + pad8(size)
	if used > len(b) {
		used = len(b)
	}
	v := podValue{Type: typ}
	switch typ {
	case podTypeInt, podTypeID, podTypeBool:
		if size < 4 {
			return v, 0, errPod
		}
		v.Num = int64(int32(binary.LittleEndian.Uint32(body)))
	case podTypeLong:
		if size < 8 {
			return v, 0, errPod
		}
		v.Num = int64(binary.LittleEndian.Uint64(body))
	case podTypeString:
		v.Str = strings.TrimRight(string(body), "\x00")
	case podTypeStruct:
		for off := 0; off < len(body); {
			f, n, err := parsePod(body[off:], depth+1)
			if err != nil {
				return v, 0, err
			}
			v.Fields = append(v.Fields, f)
			off += n
		}
	}
	return v, used, nil
}

// dict reads a props dict: Struct(Int n, String k, String v, ...).
func (v podValue) dict() map[string]string {
	out := map[string]string{}
	if v.Type != podTypeStruct || len(v.Fields) == 0 {
		return out
	}
	for i := 1; i+1 < len(v.Fields); i += 2 {
		out[v.Fields[i].Str] = v.Fields[i+1].Str
	}
	return out
}

// countNodes classifies one registry global.
func countNodes(c *checks.Capture, typ string, props map[string]string) {
	if !strings.HasSuffix(typ, ":Node") {
		return
	}
	switch props["media.class"] {
	case "Stream/Input/Audio":
		c.Audio++
	case "Stream/Input/Video":
		c.Video++
	case "Video/Source":
		name := strings.ToLower(props["node.name"] + " " + props["media.name"] + " " + props["node.description"])
		for _, k := range []string{"screencast", "screen-cast", "screen cast", "xdpw", "gnome-shell", "mutter", "kwin", "obs"} {
			if strings.Contains(name, k) {
				c.Screencast++
				return
			}
		}
	}
}

// PipeWireCapture connects to the PipeWire socket and counts capture and screencast nodes.
func PipeWireCapture(socket string) (checks.Capture, error) {
	var c checks.Capture
	if socket == "" {
		return c, errors.New("pipewire: no runtime directory")
	}
	if _, err := os.Stat(socket); err != nil {
		return c, fmt.Errorf("pipewire: %w", err)
	}
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		return c, fmt.Errorf("pipewire: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(pwReadDeadline))
	var out []byte
	out = append(out, pwMessage(pwCoreID, pwCoreHello, 0, podStruct(podInt(pwVersion)))...)
	out = append(out, pwMessage(pwClientID, pwClientUpdate, 1, podStruct(podDict("application.name", "lethe-agent")))...)
	out = append(out, pwMessage(pwCoreID, pwCoreGetRegistry, 2, podStruct(podInt(pwVersion), podInt(pwRegistryID)))...)
	out = append(out, pwMessage(pwCoreID, pwCoreSync, 3, podStruct(podInt(pwCoreID), podInt(pwSyncSeq)))...)
	if _, err := conn.Write(out); err != nil {
		return c, fmt.Errorf("pipewire: %w", err)
	}
	hdr := make([]byte, 16)
	for {
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return c, fmt.Errorf("pipewire: %w", err)
		}
		id := binary.LittleEndian.Uint32(hdr[0:])
		w := binary.LittleEndian.Uint32(hdr[4:])
		op, size := uint8(w>>24), int(w&0xffffff)
		if size > pwMaxMessage {
			return c, errors.New("pipewire: message too large")
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(conn, body); err != nil {
			return c, fmt.Errorf("pipewire: %w", err)
		}
		v, _, err := parsePod(body, 0)
		if err != nil {
			continue // a message we cannot read is skipped, never trusted
		}
		switch {
		case id == pwRegistryID && op == pwEvGlobal && len(v.Fields) >= 5:
			countNodes(&c, v.Fields[2].Str, v.Fields[4].dict())
		case id == pwCoreID && op == pwEvCorePing && len(v.Fields) >= 2:
			_, _ = conn.Write(pwMessage(pwCoreID, pwCorePong, 4, podStruct(podInt(int32(v.Fields[0].Num)), podInt(int32(v.Fields[1].Num)))))
		case id == pwCoreID && op == pwEvCoreError:
			return c, errors.New("pipewire: the server returned an error")
		case id == pwCoreID && op == pwEvCoreDone && len(v.Fields) >= 2 && v.Fields[1].Num == pwSyncSeq:
			return c, nil
		}
	}
}
