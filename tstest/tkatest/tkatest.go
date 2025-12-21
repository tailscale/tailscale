// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// tkatest has functions for creating a mock control server that responds
// to TKA endpoints.
package tkatest

import (
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log"
	"net/http"

	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

func serverError(w http.ResponseWriter, format string, a ...any) error {
	err := fmt.Sprintf(format, a...)
	http.Error(w, err, 500)
	log.Printf("returning HTTP 500 error: %v", err)
	return errors.New(err)
}

func userError(w http.ResponseWriter, format string, a ...any) error {
	err := fmt.Sprintf(format, a...)
	http.Error(w, err, 400)
	return errors.New(err)
}

// HandleTKAInitBegin handles a request to /machine/tka/init/begin.
//
// If the request contains a valid genesis AUM, it sends a response to the
// client, and returns the AUM to the caller.
func HandleTKAInitBegin(w http.ResponseWriter, r *http.Request, nodes iter.Seq[*tailcfg.Node]) (*tka.AUM, error) {
	var req *tailcfg.TKAInitBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, userError(w, "Decode: %v", err)
	}
	var aum tka.AUM
	if err := aum.Unserialize(req.GenesisAUM); err != nil {
		return nil, userError(w, "invalid genesis AUM: %v", err)
	}
	beginResp := tailcfg.TKAInitBeginResponse{}
	for n := range nodes {
		beginResp.NeedSignatures = append(
			beginResp.NeedSignatures,
			tailcfg.TKASignInfo{
				NodeID:     n.ID,
				NodePublic: n.Key,
			},
		)
	}

	w.WriteHeader(200)
	if err := json.NewEncoder(w).Encode(beginResp); err != nil {
		return nil, serverError(w, "Encode: %v", err)
	}
	return &aum, nil
}

// HandleTKAInitFinish handles a request to /machine/tka/init/finish.
//
// It sends a response to the client, and gives the caller a list of node
// signatures to apply.
//
// This method assumes that the node signatures are valid, and does not
// verify them with the supplied public key.
func HandleTKAInitFinish(w http.ResponseWriter, r *http.Request) (map[tailcfg.NodeID]tkatype.MarshaledSignature, error) {
	var req *tailcfg.TKAInitFinishRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, userError(w, "Decode: %v", err)
	}

	w.WriteHeader(200)
	w.Write([]byte("{}"))

	return req.Signatures, nil
}

// HandleTKABootstrap handles a request to /tka/bootstrap.
//
// If the request is valid, it sends a response to the client, and returns
// the parsed request to the caller.
func HandleTKABootstrap(w http.ResponseWriter, r *http.Request, resp tailcfg.TKABootstrapResponse) (*tailcfg.TKABootstrapRequest, error) {
	req := new(tailcfg.TKABootstrapRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, userError(w, "Decode: %v", err)
	}
	if req.Version != tailcfg.CurrentCapabilityVersion {
		return nil, userError(w, "bootstrap CapVer = %v, want %v", req.Version, tailcfg.CurrentCapabilityVersion)
	}

	w.WriteHeader(200)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return nil, serverError(w, "Encode: %v", err)
	}
	return req, nil
}

func HandleTKASyncOffer(w http.ResponseWriter, r *http.Request, authority *tka.Authority, chonk tka.Chonk) error {
	body := new(tailcfg.TKASyncOfferRequest)
	if err := json.NewDecoder(r.Body).Decode(body); err != nil {
		return userError(w, "Decode: %v", err)
	}

	log.Printf("got sync offer:\n%+v", body)

	nodeOffer, err := tka.ToSyncOffer(body.Head, body.Ancestors)
	if err != nil {
		return userError(w, "ToSyncOffer: %v", err)
	}

	controlOffer, err := authority.SyncOffer(chonk)
	if err != nil {
		return serverError(w, "authority.SyncOffer: %v", err)
	}
	sendAUMs, err := authority.MissingAUMs(chonk, nodeOffer)
	if err != nil {
		return serverError(w, "authority.MissingAUMs: %v", err)
	}

	head, ancestors, err := tka.FromSyncOffer(controlOffer)
	if err != nil {
		return serverError(w, "FromSyncOffer: %v", err)
	}
	resp := tailcfg.TKASyncOfferResponse{
		Head:        head,
		Ancestors:   ancestors,
		MissingAUMs: make([]tkatype.MarshaledAUM, len(sendAUMs)),
	}
	for i, a := range sendAUMs {
		resp.MissingAUMs[i] = a.Serialize()
	}

	log.Printf("responding to sync offer with:\n%+v", resp)
	w.WriteHeader(200)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return serverError(w, "Encode: %v", err)
	}
	return nil
}

// HandleTKASign handles a request to /machine/tka/sign.
//
// If the signature request is valid, it sends a response to the client, and
// gives the caller the signature and public key of the node being signed.
func HandleTKASign(w http.ResponseWriter, r *http.Request, authority *tka.Authority) (*tkatype.MarshaledSignature, *key.NodePublic, error) {
	req := new(tailcfg.TKASubmitSignatureRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return nil, nil, userError(w, "Decode: %v", err)
	}
	if req.Version != tailcfg.CurrentCapabilityVersion {
		return nil, nil, userError(w, "sign CapVer = %v, want %v", req.Version, tailcfg.CurrentCapabilityVersion)
	}

	var sig tka.NodeKeySignature
	if err := sig.Unserialize(req.Signature); err != nil {
		return nil, nil, userError(w, "malformed signature: %v", err)
	}
	var keyBeingSigned key.NodePublic
	if err := keyBeingSigned.UnmarshalBinary(sig.Pubkey); err != nil {
		return nil, nil, userError(w, "malformed signature pubkey: %v", err)
	}
	if err := authority.NodeKeyAuthorized(keyBeingSigned, req.Signature); err != nil {
		return nil, nil, userError(w, "signature does not verify: %v", err)
	}

	w.WriteHeader(200)
	if err := json.NewEncoder(w).Encode(tailcfg.TKASubmitSignatureResponse{}); err != nil {
		return nil, nil, serverError(w, "Encode: %v", err)
	}
	return &req.Signature, &keyBeingSigned, nil
}

// HandleTKASyncSend handles a request to /machine/tka/send.
//
// If the request is valid, it adds the new AUMs to the authority, and sends
// a response to the client with the new head.
func HandleTKASyncSend(w http.ResponseWriter, r *http.Request, authority *tka.Authority, chonk tka.Chonk) error {
	body := new(tailcfg.TKASyncSendRequest)
	if err := json.NewDecoder(r.Body).Decode(body); err != nil {
		return userError(w, "Decode: %v", err)
	}
	log.Printf("got sync send:\n%+v", body)

	var remoteHead tka.AUMHash
	if err := remoteHead.UnmarshalText([]byte(body.Head)); err != nil {
		return userError(w, "head unmarshal: %v", err)
	}
	toApply := make([]tka.AUM, len(body.MissingAUMs))
	for i, a := range body.MissingAUMs {
		if err := toApply[i].Unserialize(a); err != nil {
			return userError(w, "decoding missingAUM[%d]: %v", i, err)
		}
	}

	if len(toApply) > 0 {
		if err := authority.Inform(chonk, toApply); err != nil {
			return serverError(w, "control.Inform(%+v) failed: %v", toApply, err)
		}
	}
	head, err := authority.Head().MarshalText()
	if err != nil {
		return serverError(w, "head marshal: %v", err)
	}

	resp := tailcfg.TKASyncSendResponse{
		Head: string(head),
	}
	w.WriteHeader(200)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return serverError(w, "Encode: %v", err)
	}
	return nil
}
