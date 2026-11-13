package sio

import (
	"bytes"
	"encoding/json"
	"testing"
)

func i64(v int64) *int64 { return &v }

func TestPacketEncodeDecode(t *testing.T) {
	cases := []struct {
		pkt  Packet
		want string
	}{
		{Packet{Type: PacketConnect, Namespace: "/"}, "0"},
		{Packet{Type: PacketConnect, Namespace: "/admin", Data: json.RawMessage(`{"token":"x"}`)}, `0/admin,{"token":"x"}`},
		{Packet{Type: PacketDisconnect, Namespace: "/admin"}, "1/admin,"},
		{Packet{Type: PacketEvent, Namespace: "/", Data: json.RawMessage(`["hello",1]`)}, `2["hello",1]`},
		{Packet{Type: PacketEvent, Namespace: "/admin", ID: i64(12), Data: json.RawMessage(`["x"]`)}, `2/admin,12["x"]`},
		{Packet{Type: PacketAck, Namespace: "/", ID: i64(3), Data: json.RawMessage(`[]`)}, `33[]`},
		{Packet{Type: PacketConnectError, Namespace: "/", Data: json.RawMessage(`{"message":"no"}`)}, `4{"message":"no"}`},
		{Packet{Type: PacketBinaryEvent, Namespace: "/", Data: json.RawMessage(`["up",{"_placeholder":true,"num":0}]`), Buffers: [][]byte{{1, 2}}},
			`51-["up",{"_placeholder":true,"num":0}]`},
		{Packet{Type: PacketBinaryAck, Namespace: "/admin", ID: i64(7), Data: json.RawMessage(`[{"_placeholder":true,"num":0},{"_placeholder":true,"num":1}]`), Buffers: [][]byte{{1}, {2}}},
			`62-/admin,7[{"_placeholder":true,"num":0},{"_placeholder":true,"num":1}]`},
	}
	for _, c := range cases {
		got := c.pkt.Encode()
		if got != c.want {
			t.Errorf("Encode = %q, want %q", got, c.want)
			continue
		}
		d, err := DecodePacket(got)
		if err != nil {
			t.Fatalf("Decode(%q): %v", got, err)
		}
		if d.Type != c.pkt.Type || d.Namespace != NormalizeNamespace(c.pkt.Namespace) {
			t.Errorf("Decode(%q) type/ns = %v %q", got, d.Type, d.Namespace)
		}
		if (d.ID == nil) != (c.pkt.ID == nil) || (d.ID != nil && *d.ID != *c.pkt.ID) {
			t.Errorf("Decode(%q) id mismatch", got)
		}
		if !bytes.Equal(d.Data, c.pkt.Data) {
			t.Errorf("Decode(%q) data = %s", got, d.Data)
		}
		if d.Attachments != len(c.pkt.Buffers) {
			t.Errorf("Decode(%q) attachments = %d", got, d.Attachments)
		}
	}
}

func TestDecodePacketErrors(t *testing.T) {
	for _, s := range []string{"", "9", "5[", `2["unterminated`, "5x-[]"} {
		if _, err := DecodePacket(s); err == nil {
			t.Errorf("DecodePacket(%q) succeeded", s)
		}
	}
	// Namespace without trailing comma and no payload.
	p, err := DecodePacket("1/chat")
	if err != nil || p.Namespace != "/chat" || p.Type != PacketDisconnect {
		t.Fatalf("got %+v %v", p, err)
	}
}

func TestPollingPayload(t *testing.T) {
	pkts := []EPacket{TextPacket(EMessage, `2["a"]`), BinaryPacket([]byte{0, 1, 2, 255}), TextPacket(EPing, "")}
	enc := EncodePolling(pkts)
	if want := "4" + `2["a"]` + "\x1ebAAEC/w==\x1e2"; string(enc) != want {
		t.Fatalf("EncodePolling = %q, want %q", enc, want)
	}
	dec, err := DecodePolling(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec) != 3 || dec[0].Type != EMessage || !dec[1].Binary || !bytes.Equal(dec[1].Data, []byte{0, 1, 2, 255}) || dec[2].Type != EPing {
		t.Fatalf("DecodePolling = %+v", dec)
	}
	if _, err := DecodePolling([]byte("4a\x1e\x1e2")); err == nil {
		t.Fatal("expected error for empty record")
	}
	if _, err := DecodePolling([]byte("b!!!")); err == nil {
		t.Fatal("expected error for bad base64")
	}
}

func TestWSFrame(t *testing.T) {
	bin, b := TextPacket(EPing, "probe").WSFrame()
	if bin || string(b) != "2probe" {
		t.Fatalf("got %v %q", bin, b)
	}
	bin, b = BinaryPacket([]byte{9}).WSFrame()
	if !bin || !bytes.Equal(b, []byte{9}) {
		t.Fatalf("got %v %q", bin, b)
	}
	p, err := DecodeWSFrame(false, []byte(`0{"sid":"abc","upgrades":[],"pingInterval":100,"pingTimeout":200,"maxPayload":10}`))
	if err != nil {
		t.Fatal(err)
	}
	hs, err := ParseHandshake(p)
	if err != nil || hs.SID != "abc" || hs.PingInterval != 100 || hs.PingTimeout != 200 || hs.MaxPayload != 10 {
		t.Fatalf("hs = %+v, %v", hs, err)
	}
	if _, err := DecodeWSFrame(false, []byte("x")); err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestPlaceholders(t *testing.T) {
	data, err := BuildArgs([]any{"up"}, []any{"name"}, [][]byte{{1}, {2}})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `["up","name",{"_placeholder":true,"num":0},{"_placeholder":true,"num":1}]` {
		t.Fatalf("BuildArgs = %s", data)
	}
	// Explicit placeholders are kept as-is.
	data, _ = BuildArgs([]any{"up"}, []any{map[string]any{"file": map[string]any{"_placeholder": true, "num": 0}}}, [][]byte{{1}})
	if string(data) != `["up",{"file":{"_placeholder":true,"num":0}}]` {
		t.Fatalf("BuildArgs explicit = %s", data)
	}
	v, _ := DecodeJSON(data)
	r, err := Reconstruct(v, [][]byte{[]byte("hi")}, BinaryValue)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(r)
	if string(out) != `["up",{"file":{"_binary":true,"base64":"aGk=","size":2}}]` {
		t.Fatalf("Reconstruct = %s", out)
	}
	if _, err := Reconstruct(v, nil, BinaryValue); err == nil {
		t.Fatal("expected missing attachment error")
	}
}
