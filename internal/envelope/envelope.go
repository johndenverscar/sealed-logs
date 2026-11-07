// Package envelope seals a chunk of log lines to a project's daily public key.
//
// Format: JSONL lines, zstd-compressed, then one HPKE seal per chunk
// (X25519 + HKDF-SHA256 + AES-256-GCM). The metadata is bound as AAD, so
// moving a chunk to another project or key fails to open.
package envelope

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/klauspost/compress/zstd"
)

const Version = 1

var (
	info  = []byte("sealed-logs/v1")
	kem   = hpke.KEM_X25519_HKDF_SHA256
	suite = hpke.NewSuite(kem, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)

	zenc, _ = zstd.NewWriter(nil)
	zdec, _ = zstd.NewReader(nil)
)

type Line struct {
	TS     time.Time         `json:"ts"`
	Level  string            `json:"level"`
	Msg    string            `json:"msg"`
	Stream string            `json:"stream,omitempty"`
	Attrs  map[string]string `json:"attrs,omitempty"`
}

// Meta is the plaintext index for a chunk. It must never contain log text.
type Meta struct {
	Project   string            `json:"project"`
	ChunkID   string            `json:"chunk_id"`
	KeyID     string            `json:"key_id"`
	SessionID string            `json:"session_id"`
	AgentID   string            `json:"agent_id"`
	Source    string            `json:"source"`
	TSMin     time.Time         `json:"ts_min"`
	TSMax     time.Time         `json:"ts_max"`
	Lines     uint32            `json:"lines"`
	Levels    map[string]uint32 `json:"levels"`
}

type Sealed struct {
	V     int    `json:"v"`
	KeyID string `json:"key_id"`
	Enc   []byte `json:"enc"`
	CT    []byte `json:"ct"`
}

// Chunk is what the collector accepts and what is stored as one object.
type Chunk struct {
	Meta   Meta   `json:"meta"`
	Sealed Sealed `json:"sealed"`
}

func GenerateKeyPair() (pub, priv []byte, err error) {
	pk, sk, err := kem.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	if pub, err = pk.MarshalBinary(); err != nil {
		return nil, nil, err
	}
	priv, err = sk.MarshalBinary()
	return pub, priv, err
}

func aad(m Meta) []byte { return []byte(m.Project + "|" + m.ChunkID + "|" + m.KeyID) }

// Seal returns the sealed chunk and the uncompressed plaintext size.
func Seal(pub []byte, m Meta, lines []Line) (Sealed, int, error) {
	var buf bytes.Buffer
	je := json.NewEncoder(&buf)
	for _, l := range lines {
		if err := je.Encode(l); err != nil {
			return Sealed{}, 0, err
		}
	}
	pt := zenc.EncodeAll(buf.Bytes(), nil)

	pk, err := kem.Scheme().UnmarshalBinaryPublicKey(pub)
	if err != nil {
		return Sealed{}, 0, err
	}
	sender, err := suite.NewSender(pk, info)
	if err != nil {
		return Sealed{}, 0, err
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return Sealed{}, 0, err
	}
	ct, err := sealer.Seal(pt, aad(m))
	if err != nil {
		return Sealed{}, 0, err
	}
	return Sealed{V: Version, KeyID: m.KeyID, Enc: enc, CT: ct}, buf.Len(), nil
}

func Open(priv []byte, m Meta, s Sealed) ([]Line, error) {
	if s.V != Version {
		return nil, errors.New("unknown envelope version")
	}
	sk, err := kem.Scheme().UnmarshalBinaryPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	recv, err := suite.NewReceiver(sk, info)
	if err != nil {
		return nil, err
	}
	opener, err := recv.Setup(s.Enc)
	if err != nil {
		return nil, err
	}
	pt, err := opener.Open(s.CT, aad(m))
	if err != nil {
		return nil, err
	}
	raw, err := zdec.DecodeAll(pt, nil)
	if err != nil {
		return nil, err
	}
	var out []Line
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var l Line
		if err := dec.Decode(&l); err == io.EOF {
			return out, nil
		} else if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
}

// SignedMessage is what keysvc signs so producers can trust a public key.
func SignedMessage(keyID string, pub []byte) []byte {
	return append([]byte("sealed-logs/v1|"+keyID+"|"), pub...)
}
