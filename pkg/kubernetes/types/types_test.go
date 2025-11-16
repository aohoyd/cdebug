package types

import (
	"encoding/json"
	"testing"

	"gotest.tools/v3/assert"
)

func TestPodJSONMarshaling(t *testing.T) {
	pod := Pod{
		APIVersion: "v1",
		Kind:       "Pod",
		Metadata: ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: PodSpec{
			Containers: []Container{
				{
					Name:  "main",
					Image: "nginx:latest",
				},
			},
		},
	}

	data, err := json.Marshal(pod)
	assert.NilError(t, err)

	var decoded Pod
	err = json.Unmarshal(data, &decoded)
	assert.NilError(t, err)
	assert.Equal(t, pod.Metadata.Name, decoded.Metadata.Name)
	assert.Equal(t, pod.Spec.Containers[0].Name, decoded.Spec.Containers[0].Name)
}

func TestEphemeralContainerJSONMarshaling(t *testing.T) {
	ec := EphemeralContainer{
		Name:                "debugger",
		Image:               "busybox",
		TargetContainerName: "main",
	}

	data, err := json.Marshal(ec)
	assert.NilError(t, err)

	var decoded EphemeralContainer
	err = json.Unmarshal(data, &decoded)
	assert.NilError(t, err)
	assert.Equal(t, ec.Name, decoded.Name)
	assert.Equal(t, ec.TargetContainerName, decoded.TargetContainerName)
}
