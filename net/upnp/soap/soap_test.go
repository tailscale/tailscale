package soap

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"testing"
)

type capturingRoundTripper struct {
	err         error
	resp        *http.Response
	capturedReq *http.Request
}

func (rt *capturingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.capturedReq = req
	return rt.resp, rt.err
}

func TestActionInputs(t *testing.T) {
	t.Parallel()
	url, err := url.Parse("http://example.com/soap")
	if err != nil {
		t.Fatal(err)
	}
	rt := &capturingRoundTripper{
		err: nil,
		resp: &http.Response{
			StatusCode: 200,
			Body: ioutil.NopCloser(bytes.NewBufferString(`
				<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
					<s:Body>
						<u:myactionResponse xmlns:u="mynamespace">
							<A>valueA</A>
							<B>valueB</B>
						</u:myactionResponse>
					</s:Body>
				</s:Envelope>
			`)),
		},
	}
	client := SOAPClient{
		EndpointURL: *url,
		HTTPClient: http.Client{
			Transport: rt,
		},
	}

	type In struct {
		Foo string
		Bar string `soap:"bar"`
		Baz string
	}
	type Out struct {
		A string
		B string
	}
	in := In{"foo", "bar", "quoted=\"baz\""}
	gotOut := Out{}
	err = client.PerformAction(context.Background(), "mynamespace", "myaction", &in, &gotOut)
	if err != nil {
		t.Fatal(err)
	}

	wantBody := (soapPrefix +
		`<u:myaction xmlns:u="mynamespace">` +
		`<Foo>foo</Foo>` +
		`<bar>bar</bar>` +
		`<Baz>quoted="baz"</Baz>` +
		`</u:myaction>` +
		soapSuffix)
	body, err := ioutil.ReadAll(rt.capturedReq.Body)
	if err != nil {
		t.Fatal(err)
	}
	gotBody := string(body)
	if wantBody != gotBody {
		t.Errorf("Bad request body\nwant: %q\n got: %q", wantBody, gotBody)
	}

	wantOut := Out{"valueA", "valueB"}
	if !reflect.DeepEqual(wantOut, gotOut) {
		t.Errorf("Bad output\nwant: %+v\n got: %+v", wantOut, gotOut)
	}
}

func TestEscapeXMLText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"abc123", "abc123"},
		{"<foo>&", "&lt;foo&gt;&amp;"},
		{"\"foo'", "\"foo'"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			got := escapeXMLText(test.input)
			if got != test.want {
				t.Errorf("want %q, got %q", test.want, got)
			}
		})
	}
}
