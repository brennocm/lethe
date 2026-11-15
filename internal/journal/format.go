package journal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	formatName    = "lethe-seg"
	formatVersion = 1
	trailerMagic  = "LETHEEND"
	trailerSize   = len(trailerMagic) + 8 + chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	maxRecordSize = 1 << 20 // a single event can never exceed 1 MiB
)

// Header is the first line of a segment file.
type Header struct {
	Format           string `json:"format"`
	V                int    `json:"v"`
	Session          string `json:"session"`
	Segment          int    `json:"segment"`
	KeyWrap          string `json:"key_wrap"`
	SensitiveKeyWrap string `json:"sensitive_key_wrap"`
}

func segmentName(n int) string { return fmt.Sprintf("segment-%06d.lseg", n) }

func recordAD(hdrHash [32]byte, index uint64) []byte {
	ad := make([]byte, 0, 32+8)
	ad = append(ad, hdrHash[:]...)
	return binary.BigEndian.AppendUint64(ad, index)
}

func trailerAD(hdrHash [32]byte, count uint64) []byte {
	ad := append([]byte("trailer\x00"), hdrHash[:]...)
	return binary.BigEndian.AppendUint64(ad, count)
}

func sealRecord(key []byte, hdrHash [32]byte, index uint64, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	body := aead.Seal(nonce, nonce, plaintext, recordAD(hdrHash, index))
	out := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(body)), uint32(len(body)))
	return append(out, body...), nil
}

func openRecord(key []byte, hdrHash [32]byte, index uint64, body []byte) ([]byte, error) {
	if len(body) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("record %d too short", index)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce, ct := body[:chacha20poly1305.NonceSizeX], body[chacha20poly1305.NonceSizeX:]
	pt, err := aead.Open(nil, nonce, ct, recordAD(hdrHash, index))
	if err != nil {
		return nil, fmt.Errorf("record %d fails authentication", index)
	}
	return pt, nil
}

func sealTrailer(key []byte, hdrHash [32]byte, count uint64) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(trailerMagic), binary.BigEndian.AppendUint64(nil, count)...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, nil, trailerAD(hdrHash, count)), nil
}

// parseTrailer returns the authenticated record count if tail is a valid trailer.
func parseTrailer(key []byte, hdrHash [32]byte, tail []byte) (uint64, bool) {
	if len(tail) != trailerSize || string(tail[:len(trailerMagic)]) != trailerMagic {
		return 0, false
	}
	count := binary.BigEndian.Uint64(tail[len(trailerMagic):])
	nonce := tail[len(trailerMagic)+8 : len(trailerMagic)+8+chacha20poly1305.NonceSizeX]
	tag := tail[len(trailerMagic)+8+chacha20poly1305.NonceSizeX:]
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return 0, false
	}
	if _, err := aead.Open(nil, nonce, tag, trailerAD(hdrHash, count)); err != nil {
		return 0, false
	}
	return count, true
}

func headerHash(line []byte) [32]byte { return sha256.Sum256(line) }
