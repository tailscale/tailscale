package testcodegen

// PingRequest with no IP and Types is a request to send an HTTP request to prove the
// long-polling client is still connected.
// PingRequest with Types and IP, will send a ping to the IP and send a POST
// request containing a PingResponse to the URL containing results.
type PingRequest struct {
	// URL is the URL to reply to the PingRequest to.
	// It will be a unique URL each time. No auth headers are necessary.
	// If the client sees multiple PingRequests with the same URL,
	// subsequent ones should be ignored.
	//
	// The HTTP method that the node should make back to URL depends on the other
	// fields of the PingRequest. If Types is defined, then URL is the URL to
	// send a POST request to. Otherwise, the node should just make a HEAD
	// request to URL.
	URL string

	// URLIsNoise, if true, means that the client should hit URL over the Noise
	// transport instead of TLS.
	URLIsNoise bool `json:",omitempty"`

	// Log is whether to log about this ping in the success case.
	// For failure cases, the client will log regardless.
	Log bool `json:",omitempty"`

	// Types is the types of ping that are initiated. Can be any PingType, comma
	// separated, e.g. "disco,TSMP"
	//
	// As a special case, if Types is "c2n", then this PingRequest is a
	// client-to-node HTTP request. The HTTP request should be handled by this
	// node's c2n handler and the HTTP response sent in a POST to URL. For c2n,
	// the value of URLIsNoise is ignored and only the Noise transport (back to
	// the control plane) will be used, as if URLIsNoise were true.
	Types string `json:",omitempty"`

	// IP is the ping target, when needed by the PingType(s) given in Types.
	IP string

	// Payload is the ping payload.
	//
	// It is only used for c2n requests, in which case it's an HTTP/1.0 or
	// HTTP/1.1-formatted HTTP request as parsable with http.ReadRequest.
	Payload []byte `json:",omitempty"`

	IntList    []int
	Uint32List []uint32

	StringPtr *string
	StructPtr *OtherStruct
	MultiPtr  ***int

	/*
		Kv1 map[string]int
		Kv2 map[int]bool
	*/

	/*
		Other       OtherStruct
		OtherSlice  []OtherStruct
		OtherMap    map[string]OtherStruct
		OtherKeyMap map[OtherStruct]bool
	*/
}

type OtherStruct struct {
	Name string
	Age  int
}
