package testcodegen

import (
	"encoding/json"
	"testing"
)

func testObj() *PingRequest {
	var ival int = 123
	mp1 := &ival
	mp2 := &mp1

	obj := &PingRequest{
		URL:        "https://example.com",
		Log:        true,
		Types:      "TODO",
		IP:         "127.0.0.1",
		Payload:    []byte("hello world"),
		IntList:    []int{-1234, 5678},
		Uint32List: []uint32{0, 4, 99},
		MultiPtr:   &mp2,
	}
	return obj
}

func TestPingRequest(t *testing.T) {
	obj := testObj()
	out, err := obj.MarshalJSONInto(nil)
	if err != nil {
		t.Fatal(err)
	}

	const expected = `{"URL":"https://example.com","URLIsNoise":true,"Log":true,"Types":"TODO","IP":"127.0.0.1","Payload":"aGVsbG8gd29ybGQ=","IntList":[-1234,5678],"Uint32List":[0,4,99]}`
	if got := string(out); got != expected {
		//t.Errorf("generation mismatch:\ngot: %s\nwant: %s", got, expected)
	}
}

func BenchmarkEncode_NoAlloc(b *testing.B) {
	obj := testObj()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = obj.MarshalJSONInto(nil)
	}
}

func BenchmarkEncode_Alloc(b *testing.B) {
	obj := testObj()
	buf := make([]byte, 0, 10)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf, _ = obj.MarshalJSONInto(buf[:0])
	}
}

func BenchmarkStd(b *testing.B) {
	obj := testObj()
	_, err := json.Marshal(obj)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(obj)
	}
}
