// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package local

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

// TailnetLockStatus fetches information about the tailnet key authority, if one is configured.
func (lc *Client) TailnetLockStatus(ctx context.Context) (*ipnstate.TailnetLockStatus, error) {
	body, err := lc.send(ctx, "GET", "/localapi/v0/tka/status", 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}
	return decodeJSON[*ipnstate.TailnetLockStatus](body)
}

// Deprecated: use [Client.TailnetLockStatus] instead.
func (lc *Client) NetworkLockStatus(ctx context.Context) (*ipnstate.TailnetLockStatus, error) {
	return lc.TailnetLockStatus(ctx)
}

// TailnetLockInit initializes the tailnet key authority.
func (lc *Client) TailnetLockInit(ctx context.Context, keys []tka.Key, disablementValues [][]byte, supportDisablement []byte) (*ipnstate.TailnetLockStatus, error) {
	var b bytes.Buffer
	type initRequest struct {
		Keys               []tka.Key
		DisablementValues  [][]byte
		SupportDisablement []byte
	}

	if err := json.NewEncoder(&b).Encode(initRequest{Keys: keys, DisablementValues: disablementValues, SupportDisablement: supportDisablement}); err != nil {
		return nil, err
	}

	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/init", 200, &b)
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}
	return decodeJSON[*ipnstate.TailnetLockStatus](body)
}

// Deprecated: use [Client.TailnetLockInit] instead.
func (lc *Client) NetworkLockInit(ctx context.Context, keys []tka.Key, disablementValues [][]byte, supportDisablement []byte) (*ipnstate.TailnetLockStatus, error) {
	return lc.TailnetLockInit(ctx, keys, disablementValues, supportDisablement)
}

// TailnetLockWrapPreauthKey wraps a pre-auth key with information to
// enable unattended bringup in the locked tailnet.
func (lc *Client) TailnetLockWrapPreauthKey(ctx context.Context, preauthKey string, tkaKey key.NLPrivate) (string, error) {
	encodedPrivate, err := tkaKey.MarshalText()
	if err != nil {
		return "", err
	}

	var b bytes.Buffer
	type wrapRequest struct {
		TSKey  string
		TKAKey string // key.NLPrivate.MarshalText
	}
	if err := json.NewEncoder(&b).Encode(wrapRequest{TSKey: preauthKey, TKAKey: string(encodedPrivate)}); err != nil {
		return "", err
	}

	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/wrap-preauth-key", 200, &b)
	if err != nil {
		return "", fmt.Errorf("error: %w", err)
	}
	return string(body), nil
}

// Deprecated: use [Client.TailnetLockWrapPreauthKey] instead.
func (lc *Client) NetworkLockWrapPreauthKey(ctx context.Context, preauthKey string, tkaKey key.NLPrivate) (string, error) {
	return lc.TailnetLockWrapPreauthKey(ctx, preauthKey, tkaKey)
}

// TailnetLockModify adds and/or removes key(s) to the tailnet key authority.
func (lc *Client) TailnetLockModify(ctx context.Context, addKeys, removeKeys []tka.Key) error {
	var b bytes.Buffer
	type modifyRequest struct {
		AddKeys    []tka.Key
		RemoveKeys []tka.Key
	}

	if err := json.NewEncoder(&b).Encode(modifyRequest{AddKeys: addKeys, RemoveKeys: removeKeys}); err != nil {
		return err
	}

	if _, err := lc.send(ctx, "POST", "/localapi/v0/tka/modify", 204, &b); err != nil {
		return fmt.Errorf("error: %w", err)
	}
	return nil
}

// Deprecated: use [Client.TailnetLockModify] instead.
func (lc *Client) NetworkLockModify(ctx context.Context, addKeys, removeKeys []tka.Key) error {
	return lc.TailnetLockModify(ctx, addKeys, removeKeys)
}

// TailnetLockSign signs the specified node-key and transmits that signature to the control plane.
// rotationPublic, if specified, must be an ed25519 public key.
func (lc *Client) TailnetLockSign(ctx context.Context, nodeKey key.NodePublic, rotationPublic []byte) error {
	var b bytes.Buffer
	type signRequest struct {
		NodeKey        key.NodePublic
		RotationPublic []byte
	}

	if err := json.NewEncoder(&b).Encode(signRequest{NodeKey: nodeKey, RotationPublic: rotationPublic}); err != nil {
		return err
	}

	if _, err := lc.send(ctx, "POST", "/localapi/v0/tka/sign", 200, &b); err != nil {
		return fmt.Errorf("error: %w", err)
	}
	return nil
}

// Deprecated: use [Client.TailnetLockSign] instead.
func (lc *Client) NetworkLockSign(ctx context.Context, nodeKey key.NodePublic, rotationPublic []byte) error {
	return lc.TailnetLockSign(ctx, nodeKey, rotationPublic)
}

// TailnetLockAffectedSigs returns all signatures signed by the specified keyID.
func (lc *Client) TailnetLockAffectedSigs(ctx context.Context, keyID tkatype.KeyID) ([]tkatype.MarshaledSignature, error) {
	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/affected-sigs", 200, bytes.NewReader(keyID))
	if err != nil {
		return nil, fmt.Errorf("error: %w", err)
	}
	return decodeJSON[[]tkatype.MarshaledSignature](body)
}

// Deprecated: use [Client.TailnetLockAffectedSigs] instead.
func (lc *Client) NetworkLockAffectedSigs(ctx context.Context, keyID tkatype.KeyID) ([]tkatype.MarshaledSignature, error) {
	return lc.TailnetLockAffectedSigs(ctx, keyID)
}

// TailnetLockLog returns up to maxEntries number of changes to tailnet-lock state.
func (lc *Client) TailnetLockLog(ctx context.Context, maxEntries int) ([]ipnstate.TailnetLockUpdate, error) {
	v := url.Values{}
	v.Set("limit", fmt.Sprint(maxEntries))
	body, err := lc.send(ctx, "GET", "/localapi/v0/tka/log?"+v.Encode(), 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[[]ipnstate.TailnetLockUpdate](body)
}

// Deprecated: use [Client.TailnetLockLog] instead.
func (lc *Client) NetworkLockLog(ctx context.Context, maxEntries int) ([]ipnstate.TailnetLockUpdate, error) {
	return lc.TailnetLockLog(ctx, maxEntries)
}

// TailnetLockForceLocalDisable forcibly shuts down tailnet lock on this node.
func (lc *Client) TailnetLockForceLocalDisable(ctx context.Context) error {
	// This endpoint expects an empty JSON stanza as the payload.
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(struct{}{}); err != nil {
		return err
	}

	if _, err := lc.send(ctx, "POST", "/localapi/v0/tka/force-local-disable", 200, &b); err != nil {
		return fmt.Errorf("error: %w", err)
	}
	return nil
}

// Deprecated: use [Client.TailnetLockForceLocalDisable] instead.
func (lc *Client) NetworkLockForceLocalDisable(ctx context.Context) error {
	return lc.TailnetLockForceLocalDisable(ctx)
}

// TailnetLockVerifySigningDeeplink verifies the tailnet lock deeplink contained
// in url and returns information extracted from it.
func (lc *Client) TailnetLockVerifySigningDeeplink(ctx context.Context, url string) (*tka.DeeplinkValidationResult, error) {
	vr := struct {
		URL string
	}{url}

	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/verify-deeplink", 200, jsonBody(vr))
	if err != nil {
		return nil, fmt.Errorf("sending verify-deeplink: %w", err)
	}

	return decodeJSON[*tka.DeeplinkValidationResult](body)
}

// Deprecated: use [Client.TailnetLockVerifySigningDeeplink] instead.
func (lc *Client) NetworkLockVerifySigningDeeplink(ctx context.Context, url string) (*tka.DeeplinkValidationResult, error) {
	return lc.TailnetLockVerifySigningDeeplink(ctx, url)
}

// TailnetLockGenRecoveryAUM generates an AUM for recovering from a tailnet-lock key compromise.
func (lc *Client) TailnetLockGenRecoveryAUM(ctx context.Context, removeKeys []tkatype.KeyID, forkFrom tka.AUMHash) ([]byte, error) {
	vr := struct {
		Keys     []tkatype.KeyID
		ForkFrom string
	}{removeKeys, forkFrom.String()}

	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/generate-recovery-aum", 200, jsonBody(vr))
	if err != nil {
		return nil, fmt.Errorf("sending generate-recovery-aum: %w", err)
	}

	return body, nil
}

// Deprecated: use [Client.TailnetLockGenRecoveryAUM] instead.
func (lc *Client) NetworkLockGenRecoveryAUM(ctx context.Context, removeKeys []tkatype.KeyID, forkFrom tka.AUMHash) ([]byte, error) {
	return lc.TailnetLockGenRecoveryAUM(ctx, removeKeys, forkFrom)
}

// TailnetLockCosignRecoveryAUM co-signs a recovery AUM using the node's tailnet lock key.
func (lc *Client) TailnetLockCosignRecoveryAUM(ctx context.Context, aum tka.AUM) ([]byte, error) {
	r := bytes.NewReader(aum.Serialize())
	body, err := lc.send(ctx, "POST", "/localapi/v0/tka/cosign-recovery-aum", 200, r)
	if err != nil {
		return nil, fmt.Errorf("sending cosign-recovery-aum: %w", err)
	}

	return body, nil
}

// Deprecated: use [Client.TailnetLockCosignRecoveryAUM] instead.
func (lc *Client) NetworkLockCosignRecoveryAUM(ctx context.Context, aum tka.AUM) ([]byte, error) {
	return lc.TailnetLockCosignRecoveryAUM(ctx, aum)
}

// TailnetLockSubmitRecoveryAUM submits a recovery AUM to the control plane.
func (lc *Client) TailnetLockSubmitRecoveryAUM(ctx context.Context, aum tka.AUM) error {
	r := bytes.NewReader(aum.Serialize())
	_, err := lc.send(ctx, "POST", "/localapi/v0/tka/submit-recovery-aum", 200, r)
	if err != nil {
		return fmt.Errorf("sending cosign-recovery-aum: %w", err)
	}
	return nil
}

// Deprecated: use [Client.TailnetLockSubmitRecoveryAUM] instead.
func (lc *Client) NetworkLockSubmitRecoveryAUM(ctx context.Context, aum tka.AUM) error {
	return lc.TailnetLockSubmitRecoveryAUM(ctx, aum)
}

// TailnetLockDisable shuts down tailnet-lock across the tailnet.
func (lc *Client) TailnetLockDisable(ctx context.Context, secret []byte) error {
	if _, err := lc.send(ctx, "POST", "/localapi/v0/tka/disable", 200, bytes.NewReader(secret)); err != nil {
		return fmt.Errorf("error: %w", err)
	}
	return nil
}

// Deprecated: use [Client.TailnetLockDisable] instead.
func (lc *Client) NetworkLockDisable(ctx context.Context, secret []byte) error {
	return lc.TailnetLockDisable(ctx, secret)
}
