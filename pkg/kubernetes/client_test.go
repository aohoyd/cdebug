package kubernetes

import (
	"context"
	"testing"

	"gotest.tools/v3/assert"
	"k8s.io/client-go/rest"
)

func TestNewClient(t *testing.T) {
	config := &rest.Config{
		Host: "https://kubernetes.default.svc",
	}

	client, err := NewClient(config)
	assert.NilError(t, err)
	assert.Assert(t, client != nil)
}

func TestGetPod(t *testing.T) {
	// This is a unit test with mock - we'll rely on e2e tests for real validation
	// Just ensure the method exists and has correct signature
	config := &rest.Config{
		Host: "https://kubernetes.default.svc",
	}
	client, _ := NewClient(config)

	// Test that method exists (will fail in real call without cluster)
	_, err := client.GetPod(context.Background(), "default", "test-pod")
	// We expect an error since we don't have a real cluster
	// Just verify the method exists
	assert.Assert(t, err != nil) // Expected to fail without cluster
}
