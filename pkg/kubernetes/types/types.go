package types

import (
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ObjectMeta contains minimal metadata for Kubernetes objects
type ObjectMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// Pod represents a minimal Kubernetes Pod
type Pod struct {
	APIVersion string     `json:"apiVersion,omitempty"`
	Kind       string     `json:"kind,omitempty"`
	Metadata   ObjectMeta `json:"metadata"`
	Spec       PodSpec    `json:"spec"`
	Status     PodStatus  `json:"status,omitzero"`
}

// GetObjectKind implements runtime.Object
func (p *Pod) GetObjectKind() schema.ObjectKind {
	return p
}

// DeepCopyObject implements runtime.Object
func (p *Pod) DeepCopyObject() runtime.Object {
	if p == nil {
		return nil
	}
	// For our purposes, a shallow copy is sufficient
	// as we don't modify the objects after watch events
	out := new(Pod)
	*out = *p
	return out
}

// GroupVersionKind implements schema.ObjectKind
func (p *Pod) GroupVersionKind() schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Pod",
	}
}

// SetGroupVersionKind implements schema.ObjectKind
func (p *Pod) SetGroupVersionKind(gvk schema.GroupVersionKind) {
	p.APIVersion = gvk.GroupVersion().String()
	p.Kind = gvk.Kind
}

// PodSpec describes the pod specification
type PodSpec struct {
	Containers          []Container          `json:"containers"`
	EphemeralContainers []EphemeralContainer `json:"ephemeralContainers,omitempty"`
	SecurityContext     *PodSecurityContext  `json:"securityContext,omitempty"`
	NodeName            string               `json:"nodeName,omitempty"`
	RestartPolicy       string               `json:"restartPolicy,omitempty"`
	HostNetwork         bool                 `json:"hostNetwork,omitempty"`
	HostPID             bool                 `json:"hostPID,omitempty"`
	HostIPC             bool                 `json:"hostIPC,omitempty"`
	Tolerations         []Toleration         `json:"tolerations,omitempty"`
	Volumes             []Volume             `json:"volumes,omitempty"`
}

// PodStatus represents pod status
type PodStatus struct {
	InitContainerStatuses      []ContainerStatus `json:"initContainerStatuses,omitempty"`
	ContainerStatuses          []ContainerStatus `json:"containerStatuses,omitempty"`
	EphemeralContainerStatuses []ContainerStatus `json:"ephemeralContainerStatuses,omitempty"`
}

// Container represents a container in a pod
type Container struct {
	Name                     string           `json:"name"`
	Image                    string           `json:"image"`
	Command                  []string         `json:"command,omitempty"`
	Args                     []string         `json:"args,omitempty"`
	Env                      []EnvVar         `json:"env,omitempty"`
	VolumeMounts             []VolumeMount    `json:"volumeMounts,omitempty"`
	SecurityContext          *SecurityContext `json:"securityContext,omitempty"`
	ImagePullPolicy          string           `json:"imagePullPolicy,omitempty"`
	Stdin                    bool             `json:"stdin,omitempty"`
	TTY                      bool             `json:"tty,omitempty"`
	TerminationMessagePolicy string           `json:"terminationMessagePolicy,omitempty"`
}

// EphemeralContainer represents an ephemeral debug container
type EphemeralContainer struct {
	Name                     string           `json:"name"`
	Image                    string           `json:"image"`
	Command                  []string         `json:"command,omitempty"`
	Args                     []string         `json:"args,omitempty"`
	Env                      []EnvVar         `json:"env,omitempty"`
	VolumeMounts             []VolumeMount    `json:"volumeMounts,omitempty"`
	SecurityContext          *SecurityContext `json:"securityContext,omitempty"`
	ImagePullPolicy          string           `json:"imagePullPolicy,omitempty"`
	Stdin                    bool             `json:"stdin,omitempty"`
	TTY                      bool             `json:"tty,omitempty"`
	TerminationMessagePolicy string           `json:"terminationMessagePolicy,omitempty"`
	TargetContainerName      string           `json:"targetContainerName,omitempty"`
}

// SecurityContext holds security configuration
type SecurityContext struct {
	Privileged             *bool  `json:"privileged,omitempty"`
	RunAsUser              *int64 `json:"runAsUser,omitempty"`
	RunAsGroup             *int64 `json:"runAsGroup,omitempty"`
	RunAsNonRoot           *bool  `json:"runAsNonRoot,omitempty"`
	ReadOnlyRootFilesystem *bool  `json:"readOnlyRootFilesystem,omitempty"`
}

// PodSecurityContext holds pod-level security attributes
type PodSecurityContext struct {
	RunAsUser    *int64 `json:"runAsUser,omitempty"`
	RunAsGroup   *int64 `json:"runAsGroup,omitempty"`
	RunAsNonRoot *bool  `json:"runAsNonRoot,omitempty"`
}

// ContainerStatus contains details about container status
type ContainerStatus struct {
	Name                 string         `json:"name"`
	State                ContainerState `json:"state,omitempty"`
	LastTerminationState ContainerState `json:"lastTerminationState,omitempty"`
}

// ContainerState holds container state information
type ContainerState struct {
	Running    *ContainerStateRunning    `json:"running,omitempty"`
	Terminated *ContainerStateTerminated `json:"terminated,omitempty"`
	Waiting    *ContainerStateWaiting    `json:"waiting,omitempty"`
}

// ContainerStateRunning indicates container is running
type ContainerStateRunning struct {
	StartedAt string `json:"startedAt,omitempty"`
}

// ContainerStateTerminated indicates container has terminated
type ContainerStateTerminated struct {
	ExitCode int32  `json:"exitCode"`
	Reason   string `json:"reason,omitempty"`
	Message  string `json:"message,omitempty"`
}

// ContainerStateWaiting indicates container is waiting
type ContainerStateWaiting struct {
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// VolumeMount describes a volume mount
type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	SubPath   string `json:"subPath,omitempty"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

// Volume represents a pod volume
type Volume struct {
	Name         string       `json:"name"`
	VolumeSource VolumeSource `json:",inline"`
}

// VolumeSource represents the source of a volume
type VolumeSource struct {
	HostPath *HostPathVolumeSource `json:"hostPath,omitempty"`
	// Add other volume types as needed
}

// HostPathVolumeSource represents a host path volume
type HostPathVolumeSource struct {
	Path string `json:"path"`
	Type string `json:"type,omitempty"`
}

// Toleration allows pods to schedule on nodes with matching taints
type Toleration struct {
	Key      string `json:"key,omitempty"`
	Operator string `json:"operator,omitempty"`
	Value    string `json:"value,omitempty"`
	Effect   string `json:"effect,omitempty"`
}

// EnvVar represents an environment variable
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// Constants for string-based enums
const (
	RestartPolicyNever  = "Never"
	RestartPolicyAlways = "Always"

	PullIfNotPresent = "IfNotPresent"
	PullAlways       = "Always"

	TolerationOpExists = "Exists"

	TerminationMessageReadFile = "File"
)

// PodEventType defines the possible types of events.
type PodEventType string

const (
	PodAdded    PodEventType = "ADDED"
	PodModified PodEventType = "MODIFIED"
	PodDeleted  PodEventType = "DELETED"
	PodBookmark PodEventType = "BOOKMARK"
	PodError    PodEventType = "ERROR"
)

type PodEvent struct {
	Type PodEventType
	Pod  *Pod
}
