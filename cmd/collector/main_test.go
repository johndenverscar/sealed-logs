package main

import (
	"encoding/json"
	"testing"

	"sealedlogs/internal/auth"
	"sealedlogs/internal/envelope"
)

func TestValidate(t *testing.T) {
	pub, _, _ := envelope.GenerateKeyPair()
	m := envelope.Meta{Project: "p_demo", ChunkID: "c_1", KeyID: "p_demo/2026-01-02/g1"}
	sl, _, _ := envelope.Seal(pub, m, []envelope.Line{{Level: "info", Msg: "hello"}})
	good, _ := json.Marshal(envelope.Chunk{Meta: m, Sealed: sl})
	producer := &auth.Claims{Project: "p_demo", Role: auth.RoleProducer}

	if _, reason := validate(producer, good); reason != "" {
		t.Fatalf("valid chunk refused: %s", reason)
	}

	foreignKey := m
	foreignKey.KeyID = "p_other/2026-01-02/g1"
	fk, _ := json.Marshal(envelope.Chunk{Meta: foreignKey, Sealed: envelope.Sealed{V: 1, KeyID: foreignKey.KeyID, Enc: sl.Enc, CT: sl.CT}})

	short := sl
	short.CT = short.CT[:8]
	sh, _ := json.Marshal(envelope.Chunk{Meta: m, Sealed: short})

	// A real sealed chunk with the plaintext riding alongside it.
	var smuggle map[string]any
	_ = json.Unmarshal(good, &smuggle)
	smuggle["lines"] = []string{"card 4111 1111 1111 1111"}
	sm, _ := json.Marshal(smuggle)

	refused := map[string]struct {
		claims *auth.Claims
		body   string
	}{
		"plaintext lines":          {producer, `{"lines":[{"msg":"card 4111"}]}`},
		"extra field beside seal":  {producer, `{"meta":{},"sealed":{},"msg":"card 4111"}`},
		"not json":                 {producer, `card 4111`},
		"sealed chunk + plaintext": {producer, string(sm)},
		"another project's chunk":  {&auth.Claims{Project: "p_other", Role: auth.RoleProducer}, string(good)},
		"another project's key":    {producer, string(fk)},
		"truncated ciphertext":     {producer, string(sh)},
	}
	for name, c := range refused {
		if _, reason := validate(c.claims, []byte(c.body)); reason == "" {
			t.Errorf("%s: accepted", name)
		}
	}
}
