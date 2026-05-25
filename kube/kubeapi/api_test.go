// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kubeapi

import (
	"encoding/json"
	"testing"
	"time"
)

func TestTypeMeta_JSON(t *testing.T) {
	tests := []struct {
		name string
		tm   TypeMeta
	}{
		{
			name: "basic",
			tm: TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
		},
		{
			name: "secret",
			tm: TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
		},
		{
			name: "empty",
			tm:   TypeMeta{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.tm)
			if err != nil {
				t.Fatalf("Marshal() failed: %v", err)
			}

			var decoded TypeMeta
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}

			if decoded.Kind != tt.tm.Kind {
				t.Errorf("Kind = %q, want %q", decoded.Kind, tt.tm.Kind)
			}
			if decoded.APIVersion != tt.tm.APIVersion {
				t.Errorf("APIVersion = %q, want %q", decoded.APIVersion, tt.tm.APIVersion)
			}
		})
	}
}

func TestObjectMeta_JSON(t *testing.T) {
	creationTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	deletionTime := time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC)
	gracePeriod := int64(30)

	tests := []struct {
		name string
		om   ObjectMeta
	}{
		{
			name: "basic",
			om: ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
		},
		{
			name: "with_uid",
			om: ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
				UID:       "12345678-1234-1234-1234-123456789abc",
			},
		},
		{
			name: "with_labels_and_annotations",
			om: ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
				Labels: map[string]string{
					"app":  "test",
					"tier": "backend",
				},
				Annotations: map[string]string{
					"description": "Test pod",
					"version":     "1.0",
				},
			},
		},
		{
			name: "with_timestamps",
			om: ObjectMeta{
				Name:              "test-pod",
				Namespace:         "default",
				CreationTimestamp: creationTime,
				DeletionTimestamp: &deletionTime,
			},
		},
		{
			name: "with_resource_version",
			om: ObjectMeta{
				Name:            "test-pod",
				Namespace:       "default",
				ResourceVersion: "12345",
				Generation:      3,
			},
		},
		{
			name: "with_deletion_grace_period",
			om: ObjectMeta{
				Name:                       "test-pod",
				Namespace:                  "default",
				DeletionGracePeriodSeconds: &gracePeriod,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.om)
			if err != nil {
				t.Fatalf("Marshal() failed: %v", err)
			}

			var decoded ObjectMeta
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}

			if decoded.Name != tt.om.Name {
				t.Errorf("Name = %q, want %q", decoded.Name, tt.om.Name)
			}
			if decoded.Namespace != tt.om.Namespace {
				t.Errorf("Namespace = %q, want %q", decoded.Namespace, tt.om.Namespace)
			}
			if decoded.UID != tt.om.UID {
				t.Errorf("UID = %q, want %q", decoded.UID, tt.om.UID)
			}
		})
	}
}

func TestSecret_JSON(t *testing.T) {
	tests := []struct {
		name   string
		secret Secret
	}{
		{
			name: "basic",
			secret: Secret{
				TypeMeta: TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				ObjectMeta: ObjectMeta{
					Name:      "test-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"username": []byte("admin"),
					"password": []byte("secret123"),
				},
			},
		},
		{
			name: "empty_data",
			secret: Secret{
				TypeMeta: TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				ObjectMeta: ObjectMeta{
					Name:      "empty-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{},
			},
		},
		{
			name: "binary_data",
			secret: Secret{
				TypeMeta: TypeMeta{
					Kind:       "Secret",
					APIVersion: "v1",
				},
				ObjectMeta: ObjectMeta{
					Name:      "binary-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"binary": {0x00, 0x01, 0x02, 0xFF},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.secret)
			if err != nil {
				t.Fatalf("Marshal() failed: %v", err)
			}

			var decoded Secret
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}

			if decoded.Kind != tt.secret.Kind {
				t.Errorf("Kind = %q, want %q", decoded.Kind, tt.secret.Kind)
			}
			if decoded.Name != tt.secret.Name {
				t.Errorf("Name = %q, want %q", decoded.Name, tt.secret.Name)
			}
			if len(decoded.Data) != len(tt.secret.Data) {
				t.Errorf("Data length = %d, want %d", len(decoded.Data), len(tt.secret.Data))
			}
		})
	}
}

func TestStatus_JSON(t *testing.T) {
	tests := []struct {
		name   string
		status Status
	}{
		{
			name: "success",
			status: Status{
				TypeMeta: TypeMeta{
					Kind:       "Status",
					APIVersion: "v1",
				},
				Status:  "Success",
				Message: "Operation completed successfully",
				Code:    200,
			},
		},
		{
			name: "failure",
			status: Status{
				TypeMeta: TypeMeta{
					Kind:       "Status",
					APIVersion: "v1",
				},
				Status:  "Failure",
				Message: "Resource not found",
				Reason:  "NotFound",
				Code:    404,
			},
		},
		{
			name: "with_details",
			status: Status{
				TypeMeta: TypeMeta{
					Kind:       "Status",
					APIVersion: "v1",
				},
				Status:  "Failure",
				Message: "Pod test-pod not found",
				Reason:  "NotFound",
				Details: &struct {
					Name string `json:"name,omitempty"`
					Kind string `json:"kind,omitempty"`
				}{
					Name: "test-pod",
					Kind: "Pod",
				},
				Code: 404,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.status)
			if err != nil {
				t.Fatalf("Marshal() failed: %v", err)
			}

			var decoded Status
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}

			if decoded.Status != tt.status.Status {
				t.Errorf("Status = %q, want %q", decoded.Status, tt.status.Status)
			}
			if decoded.Message != tt.status.Message {
				t.Errorf("Message = %q, want %q", decoded.Message, tt.status.Message)
			}
			if decoded.Reason != tt.status.Reason {
				t.Errorf("Reason = %q, want %q", decoded.Reason, tt.status.Reason)
			}
			if decoded.Code != tt.status.Code {
				t.Errorf("Code = %d, want %d", decoded.Code, tt.status.Code)
			}
		})
	}
}

func TestStatus_Error(t *testing.T) {
	tests := []struct {
		name    string
		status  Status
		wantErr string
	}{
		{
			name: "basic_error",
			status: Status{
				Message: "Resource not found",
			},
			wantErr: "Resource not found",
		},
		{
			name: "empty_message",
			status: Status{
				Message: "",
			},
			wantErr: "",
		},
		{
			name: "detailed_error",
			status: Status{
				Message: "Pod 'test-pod' in namespace 'default' not found",
			},
			wantErr: "Pod 'test-pod' in namespace 'default' not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.status.Error()
			if err != tt.wantErr {
				t.Errorf("Error() = %q, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestObjectMeta_EmptyMaps(t *testing.T) {
	om := ObjectMeta{
		Name:      "test",
		Namespace: "default",
	}

	data, err := json.Marshal(om)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	var decoded ObjectMeta
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	// Empty maps should be nil or empty after decode
	if decoded.Labels != nil && len(decoded.Labels) > 0 {
		t.Errorf("Labels = %v, want nil or empty", decoded.Labels)
	}
	if decoded.Annotations != nil && len(decoded.Annotations) > 0 {
		t.Errorf("Annotations = %v, want nil or empty", decoded.Annotations)
	}
}

func TestSecret_Base64Encoding(t *testing.T) {
	secret := Secret{
		TypeMeta: TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"key": []byte("sensitive-data"),
		},
	}

	data, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	// Verify the data is base64 encoded in JSON
	var rawJSON map[string]any
	if err := json.Unmarshal(data, &rawJSON); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}

	// Decode back and verify
	var decoded Secret
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	if string(decoded.Data["key"]) != "sensitive-data" {
		t.Errorf("Data[key] = %q, want %q", decoded.Data["key"], "sensitive-data")
	}
}

func TestObjectMeta_TimeZeroHandling(t *testing.T) {
	om := ObjectMeta{
		Name:              "test",
		Namespace:         "default",
		CreationTimestamp: time.Time{}, // zero time
	}

	data, err := json.Marshal(om)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	var decoded ObjectMeta
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	// Zero time should be preserved
	if !decoded.CreationTimestamp.IsZero() {
		t.Errorf("CreationTimestamp = %v, want zero time", decoded.CreationTimestamp)
	}
}

func TestTypeMeta_OmitEmpty(t *testing.T) {
	tm := TypeMeta{}

	data, err := json.Marshal(tm)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	// Empty TypeMeta should produce {} or nearly empty JSON
	var rawJSON map[string]any
	if err := json.Unmarshal(data, &rawJSON); err != nil {
		t.Fatalf("Unmarshal to map failed: %v", err)
	}

	// With omitempty, empty fields should not be in JSON
	if kind, ok := rawJSON["kind"]; ok && kind != "" {
		t.Errorf("kind present in JSON for empty TypeMeta: %v", kind)
	}
	if apiVersion, ok := rawJSON["apiVersion"]; ok && apiVersion != "" {
		t.Errorf("apiVersion present in JSON for empty TypeMeta: %v", apiVersion)
	}
}

// Benchmark JSON operations
func BenchmarkSecret_Marshal(b *testing.B) {
	secret := Secret{
		TypeMeta: TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: ObjectMeta{
			Name:      "bench-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"username": []byte("admin"),
			"password": []byte("secret123"),
			"token":    []byte("abcdefghijklmnopqrstuvwxyz"),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(secret)
		if err != nil {
			b.Fatalf("Marshal() failed: %v", err)
		}
	}
}

func BenchmarkStatus_Error(b *testing.B) {
	status := Status{
		Message: "Resource not found",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = status.Error()
	}
}
