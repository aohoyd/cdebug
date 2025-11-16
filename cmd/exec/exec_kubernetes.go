package exec

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"k8s.io/apimachinery/pkg/util/httpstream"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/aohoyd/cdebug/pkg/cliutil"
	ckubernetes "github.com/aohoyd/cdebug/pkg/kubernetes"
	"github.com/aohoyd/cdebug/pkg/kubernetes/types"
	"github.com/aohoyd/cdebug/pkg/tty"
	"github.com/aohoyd/cdebug/pkg/uuid"
)

// TODO: Handle exit codes - terminate the `cdebug exec` command with the same exit code as the debugger container.

func runDebuggerKubernetes(ctx context.Context, cli cliutil.CLI, opts *options) error {
	if opts.autoRemove {
		return fmt.Errorf("--rm flag is not supported for Kubernetes runtime")
	}
	if err := validateUserFlag(opts.user); err != nil {
		return err
	}

	config, namespace, err := ckubernetes.GetRESTConfig(
		opts.runtime,
		opts.kubeconfig,
		opts.kubeconfigContext,
	)
	if err != nil {
		return fmt.Errorf("error getting Kubernetes REST config: %v", err)
	}

	client, err := ckubernetes.NewClient(config)
	if err != nil {
		return fmt.Errorf("error creating Kubernetes client: %v", err)
	}

	if opts.namespace != "" {
		namespace = opts.namespace
	}
	if namespace == "" {
		namespace = "default"
	}

	var (
		podName      string
		debuggerName string
		ephemeral    bool
	)
	if strings.HasPrefix(opts.target, "node/") || strings.HasPrefix(opts.target, "nodes/") {
		podName, debuggerName, err = runNodeDebugger(ctx, cli, opts, namespace, client)
	} else {
		podName, debuggerName, err = runPodDebugger(ctx, cli, opts, namespace, client)
		ephemeral = true
	}

	if err != nil {
		return fmt.Errorf("error creating debugger: %v", err)
	}

	if opts.detach {
		attachCmd := []string{"kubectl", "attach", "-n", namespace, "-c", debuggerName}
		if opts.stdin {
			attachCmd = append(attachCmd, "-i")
		}
		if opts.tty {
			attachCmd = append(attachCmd, "-t")
		}
		attachCmd = append(attachCmd, podName)

		cli.PrintAux("Debugger container %q started in the background.\n", debuggerName)
		cli.PrintAux("Use %#q if you need to attach to it.\n", strings.Join(attachCmd, " "))
		return nil
	}

	return attachPodDebugger(
		ctx,
		cli,
		opts,
		config,
		client,
		namespace,
		podName,
		debuggerName,
		ephemeral,
	)
}

func runPodDebugger(ctx context.Context, cli cliutil.CLI, opts *options, namespace string, client *ckubernetes.Client) (string, string, error) {
	var (
		podName    string
		targetName string
	)
	opts.target = strings.TrimPrefix(opts.target, "pod/")
	opts.target = strings.TrimPrefix(opts.target, "pods/")
	if strings.Contains(opts.target, "/") {
		podName = strings.Split(opts.target, "/")[0]
		targetName = strings.Split(opts.target, "/")[1]
	} else {
		podName = opts.target
	}

	pod, err := client.GetPod(ctx, namespace, podName)
	if err != nil {
		return "", "", fmt.Errorf("error getting target pod: %v", err)
	}

	runID := uuid.ShortID()
	debuggerName := debuggerName(opts.name, runID)
	cli.PrintAux("Debugger container name: %s\n", debuggerName)

	cli.PrintAux("Starting debugger container...\n")

	useChroot := isRootUser(opts.user) && !isReadOnlyRootFS(pod, targetName) && !runsAsNonRoot(pod, targetName)
	if err := addEphemeralDebugger(
		ctx,
		cli,
		opts,
		client,
		pod,
		targetName,
		debuggerName,
		debuggerEntrypoint(cli, runID, 1, opts.image, opts.cmd, useChroot),
	); err != nil {
		return "", "", fmt.Errorf("error adding debugger container: %v", err)
	}

	return podName, debuggerName, nil
}

func runNodeDebugger(ctx context.Context, cli cliutil.CLI, opts *options, namespace string, client *ckubernetes.Client) (string, string, error) {
	opts.target = strings.TrimPrefix(opts.target, "node/")
	opts.target = strings.TrimPrefix(opts.target, "nodes/")

	runID := uuid.ShortID()
	podName := fmt.Sprintf("cdebug-%s-%s", opts.target, runID)
	debuggerName := "cdebug"
	volumeName := "host-root"

	p := &types.Pod{
		APIVersion: "v1",
		Kind:       "Pod",
		Metadata: types.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
		Spec: types.PodSpec{
			Containers: []types.Container{
				{
					Name:            debuggerName,
					Image:           opts.image,
					ImagePullPolicy: types.PullIfNotPresent,
					Command:         []string{"sh", "-c", debuggerEntrypoint(cli, runID, 1, opts.image, opts.cmd, false)},
					Stdin:           opts.stdin,
					TTY:             opts.tty,
					// Env:                   TODO...
					// VolumeDevices: 			  TODO...
					SecurityContext: &types.SecurityContext{
						Privileged: &opts.privileged,
						RunAsUser:  uidPtr(opts.user),
						RunAsGroup: gidPtr(opts.user),
					},
					TerminationMessagePolicy: types.TerminationMessageReadFile,
					VolumeMounts: []types.VolumeMount{
						{
							Name:      volumeName,
							MountPath: "/host",
						},
					},
				},
			},
			// Share host's network, PID and IPC with debug pod
			HostNetwork: true,
			HostPID:     true,
			HostIPC:     true,

			NodeName:      opts.target,
			RestartPolicy: types.RestartPolicyNever,
			Tolerations: []types.Toleration{
				{
					Operator: types.TolerationOpExists,
				},
			},
			Volumes: []types.Volume{
				{
					Name: volumeName,
					VolumeSource: types.VolumeSource{
						HostPath: &types.HostPathVolumeSource{Path: "/"},
					},
				},
			},
		},
	}

	if _, err := client.CreatePod(ctx, namespace, p); err != nil {
		return "", "", fmt.Errorf("error creating debug pod: %v", err)
	}

	return podName, debuggerName, nil
}

func addEphemeralDebugger(
	ctx context.Context,
	cli cliutil.CLI,
	opts *options,
	client *ckubernetes.Client,
	pod *types.Pod,
	targetName string,
	debuggerName string,
	entrypoint string,
) error {
	debugPod, err := withDebugContainer(cli, pod, opts, targetName, debuggerName, entrypoint)
	if err != nil {
		return err
	}

	patchData, err := json.Marshal(map[string]any{
		"spec": map[string]any{
			"ephemeralContainers": debugPod.Spec.EphemeralContainers,
		},
	})
	if err != nil {
		return fmt.Errorf("error creating patch: %v", err)
	}

	_, err = client.PatchPod(ctx, pod.Metadata.Namespace, pod.Metadata.Name, "ephemeralcontainers", patchData)
	if err != nil {
		// The apiserver will return a 404 when the EphemeralContainers feature is disabled because the `/ephemeralcontainers` subresource
		// is missing. Unlike the 404 returned by a missing pod, the status details will be empty.
		if strings.Contains(err.Error(), "404") {
			return fmt.Errorf("ephemeral containers are disabled for this cluster (error from server: %q)", err)
		}

		return err
	}

	return nil
}

func withDebugContainer(
	cli cliutil.CLI,
	pod *types.Pod,
	opts *options,
	targetName string,
	debuggerName string,
	entrypoint string,
) (*types.Pod, error) {
	ec := &types.EphemeralContainer{
		Name:            debuggerName,
		Image:           opts.image,
		ImagePullPolicy: types.PullIfNotPresent,
		Command:         []string{"sh", "-c", entrypoint},
		Stdin:           opts.stdin,
		TTY:             opts.tty,
		// Env:                   TODO...
		// VolumeDevices: 			  TODO...
		SecurityContext: &types.SecurityContext{
			Privileged: &opts.privileged,
			RunAsUser:  uidPtr(opts.user),
			RunAsGroup: gidPtr(opts.user),
		},
		TerminationMessagePolicy: types.TerminationMessageReadFile,
		TargetContainerName:      targetName,
	}

	if runsAsNonRoot(pod, targetName) && isRootUser(opts.user) {
		ec.SecurityContext.RunAsNonRoot = ptr(true)
		ec.SecurityContext.RunAsUser = preferredUID(pod, targetName)
		ec.SecurityContext.RunAsGroup = preferredGID(pod, targetName)

		cli.PrintAux("The target mandates non-root user, using %d:%d for the debugger container.\n",
			*ec.SecurityContext.RunAsUser, *ec.SecurityContext.RunAsGroup)
	}

	target := containerByName(pod, targetName)
	if target != nil && !isRootUser(opts.user) {
		// Copying volume mounts from the target container for convenience.
		// No need to copy for root user because for it, the rootfs will
		// look identical to the target container's.

		for _, vm := range target.VolumeMounts {
			if vm.SubPath == "" { // Subpath mounts are not allowed for ephemeral containers.
				ec.VolumeMounts = append(ec.VolumeMounts, vm)
			}
		}
	}

	// TODO: Consider mounting all volumes if the target container is not specified.
	//       Beware of potential path collisions.

	if opts.override != "" {
		var err error
		ec, err = ckubernetes.Override(ec, opts.override, opts.overrideType)
		if err != nil {
			return nil, fmt.Errorf("error overriding container: %v", err)
		}
	}

	// Create a copy of the pod
	copied := &types.Pod{
		APIVersion: pod.APIVersion,
		Kind:       pod.Kind,
		Metadata:   pod.Metadata,
		Spec:       pod.Spec,
		Status:     pod.Status,
	}
	copied.Spec.EphemeralContainers = append(copied.Spec.EphemeralContainers, *ec)

	return copied, nil
}

func waitForContainer(
	ctx context.Context,
	client *ckubernetes.Client,
	ns string,
	podName string,
	containerName string,
	running bool,
) (*types.Pod, error) {
	watcher, err := client.WatchPods(ctx, ns, ckubernetes.WatchOptions{
		FieldSelector: fmt.Sprintf("metadata.name=%s", podName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to watch pod: %w", err)
	}
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case ev := <-watcher.ResultChan():
			if ev.Type == types.PodDeleted {
				return nil, fmt.Errorf("pod %q was deleted", podName)
			}

			s := containerStatusByName(ev.Pod, containerName)
			if s == nil {
				continue
			}

			if s.LastTerminationState.Terminated != nil || s.State.Terminated != nil || (running && s.State.Running != nil) {
				return ev.Pod, nil
			}
		}
	}
}

func attachPodDebugger(
	ctx context.Context,
	cli cliutil.CLI,
	opts *options,
	config *restclient.Config,
	client *ckubernetes.Client,
	ns string,
	podName string,
	debuggerName string,
	ephemeral bool,
) error {
	cli.PrintAux("Waiting for debugger container...\n")
	pod, err := waitForContainer(ctx, client, ns, podName, debuggerName, true)
	if err != nil {
		return fmt.Errorf("error waiting for debugger container: %v", err)
	}

	status := containerStatusByName(pod, debuggerName)
	if status == nil {
		return fmt.Errorf("error getting debugger container %q status: %+v", debuggerName, err)
	}
	logrus.Debugf("Debugger container %q status: %+v", debuggerName, status)

	if status.State.Terminated != nil {
		dumpDebuggerLogs(ctx, client, ns, podName, debuggerName, cli.OutputStream())

		if status.State.Terminated.Reason == "Completed" {
			return nil
		}

		return fmt.Errorf("debugger container %q terminated: %s - %s (exit code: %d)",
			debuggerName,
			status.State.Terminated.Reason,
			status.State.Terminated.Message,
			status.State.Terminated.ExitCode)
	}

	var debuggerContainer *types.Container
	if ephemeral {
		debuggerContainer = ephemeralContainerByName(pod, debuggerName)
	} else {
		debuggerContainer = containerByName(pod, debuggerName)

	}
	if debuggerContainer == nil {
		return fmt.Errorf("cannot find debugger container %q in pod %q", debuggerName, podName)
	}

	if opts.tty && !debuggerContainer.TTY {
		opts.tty = false
		if !opts.quiet {
			cli.PrintErr("Warning: Unable to use a TTY - container %s did not allocate one\n", debuggerName)
		}
	} else if !opts.tty && debuggerContainer.TTY {
		// the container was launched with a TTY, so we have to force a TTY here
		// to avoid getting an error "Unrecognized input header"
		opts.tty = true
	}

	cli.PrintAux("Attaching to debugger container...\n")
	cli.PrintAux("If you don't see a command prompt, try pressing enter.\n")

	// Build attach URL
	attachURL, _ := url.Parse(config.Host)
	attachURL.Path = fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/attach", ns, podName)
	q := attachURL.Query()
	q.Set("container", debuggerName)
	q.Set("stdin", strconv.FormatBool(opts.stdin))
	q.Set("stdout", "true")
	q.Set("stderr", strconv.FormatBool(!opts.tty))
	q.Set("tty", strconv.FormatBool(opts.tty))
	attachURL.RawQuery = q.Encode()

	streamingCtx, cancelStreamingCtx := context.WithCancel(ctx)
	defer cancelStreamingCtx()

	go func() {
		_, _ = waitForContainer(ctx, client, ns, podName, debuggerName, false)
		// Debugger container is not running anymore - streaming no longer needed.
		cancelStreamingCtx()
	}()

	if err := stream(streamingCtx, cli, attachURL, config, opts.tty); err != nil {
		return fmt.Errorf("error streaming to/from debugger container: %v", err)
	}

	cli.PrintAux("Debugger container %q terminated...\n", debuggerName)

	if err := dumpDebuggerLogs(ctx, client, ns, podName, debuggerName, cli.OutputStream()); err != nil {
		return fmt.Errorf("error dumping debugger logs: %v", err)
	}

	return nil
}

func stream(
	ctx context.Context,
	cli cliutil.CLI,
	url *url.URL,
	config *restclient.Config,
	raw bool,
) error {
	var resizeQueue *tty.ResizeQueue
	if raw {
		if cli.OutputStream().IsTerminal() {
			resizeQueue = tty.NewResizeQueue(ctx, cli.OutputStream())
			resizeQueue.Start()
		}

		cli.InputStream().SetRawTerminal()
		cli.OutputStream().SetRawTerminal()
		defer func() {
			cli.InputStream().RestoreTerminal()
			cli.OutputStream().RestoreTerminal()
		}()
	}

	spdyExec, err := remotecommand.NewSPDYExecutor(config, "POST", url)
	if err != nil {
		return fmt.Errorf("cannot create SPDY executor: %w", err)
	}

	websocketExec, err := remotecommand.NewWebSocketExecutor(config, "GET", url.String())
	if err != nil {
		return fmt.Errorf("cannot create WebSocket executor: %w", err)
	}
	exec, err := remotecommand.NewFallbackExecutor(websocketExec, spdyExec, httpstream.IsUpgradeFailure)
	if err != nil {
		return fmt.Errorf("cannot create fallback executor: %w", err)
	}

	return exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:             cli.InputStream(),
		Stdout:            cli.OutputStream(),
		Stderr:            cli.ErrorStream(),
		Tty:               raw,
		TerminalSizeQueue: resizeQueue,
	})
}

func dumpDebuggerLogs(
	ctx context.Context,
	client *ckubernetes.Client,
	ns string,
	podName string,
	containerName string,
	out io.Writer,
) error {
	readCloser, err := client.GetPodLogs(ctx, ns, podName, ckubernetes.PodLogOptions{
		Container: containerName,
		Follow:    false,
	})
	if err != nil {
		return err
	}
	defer readCloser.Close()

	r := bufio.NewReader(readCloser)
	for {
		bytes, err := r.ReadBytes('\n')
		if _, err := out.Write(bytes); err != nil {
			return err
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func isReadOnlyRootFS(pod *types.Pod, containerName string) bool {
	c := containerByName(pod, containerName)
	return c != nil &&
		c.SecurityContext != nil &&
		c.SecurityContext.ReadOnlyRootFilesystem != nil &&
		*c.SecurityContext.ReadOnlyRootFilesystem
}

func runsAsNonRoot(pod *types.Pod, containerName string) bool {
	// Container security context takes precedence over pod security context.
	c := containerByName(pod, containerName)
	if c != nil && c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil && *c.SecurityContext.RunAsNonRoot {
		return true
	}

	return pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil && *pod.Spec.SecurityContext.RunAsNonRoot
}

func preferredUID(pod *types.Pod, containerName string) *int64 {
	c := containerByName(pod, containerName)
	if c != nil && c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil {
		return c.SecurityContext.RunAsUser
	}

	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsUser != nil {
		return pod.Spec.SecurityContext.RunAsUser
	}

	return ptr(int64(1000))
}

func preferredGID(pod *types.Pod, containerName string) *int64 {
	c := containerByName(pod, containerName)
	if c != nil && c.SecurityContext != nil && c.SecurityContext.RunAsGroup != nil {
		return c.SecurityContext.RunAsGroup
	}

	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsGroup != nil {
		return pod.Spec.SecurityContext.RunAsGroup
	}

	return ptr(int64(1000))
}

func containerStatusByName(pod *types.Pod, containerName string) *types.ContainerStatus {
	allContainerStatus := [][]types.ContainerStatus{
		pod.Status.InitContainerStatuses,
		pod.Status.ContainerStatuses,
		pod.Status.EphemeralContainerStatuses,
	}
	for _, statuses := range allContainerStatus {
		for i := range statuses {
			if statuses[i].Name == containerName {
				return &statuses[i]
			}
		}
	}
	return nil
}

func containerByName(pod *types.Pod, containerName string) *types.Container {
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == containerName {
			return &pod.Spec.Containers[i]
		}
	}
	return nil
}

func ephemeralContainerByName(pod *types.Pod, containerName string) *types.Container {
	for i := range pod.Spec.EphemeralContainers {
		if pod.Spec.EphemeralContainers[i].Name == containerName {
			// Convert EphemeralContainer to Container (they share same fields)
			c := &types.Container{
				Name:                     pod.Spec.EphemeralContainers[i].Name,
				Image:                    pod.Spec.EphemeralContainers[i].Image,
				Command:                  pod.Spec.EphemeralContainers[i].Command,
				Args:                     pod.Spec.EphemeralContainers[i].Args,
				Env:                      pod.Spec.EphemeralContainers[i].Env,
				VolumeMounts:             pod.Spec.EphemeralContainers[i].VolumeMounts,
				SecurityContext:          pod.Spec.EphemeralContainers[i].SecurityContext,
				ImagePullPolicy:          pod.Spec.EphemeralContainers[i].ImagePullPolicy,
				Stdin:                    pod.Spec.EphemeralContainers[i].Stdin,
				TTY:                      pod.Spec.EphemeralContainers[i].TTY,
				TerminationMessagePolicy: pod.Spec.EphemeralContainers[i].TerminationMessagePolicy,
			}
			return c
		}
	}
	return nil
}

// Allowed values:
//
//	<empty> - use the user specified in the toolkit image
//	<uid> - use the user with the specified UID (GID defaults to UID)
//	<uid>:<gid> - use the user with the specified UID and GID
func validateUserFlag(user string) error {
	user = strings.TrimSpace(user)

	if user == "" {
		return nil
	}

	var (
		parts = strings.Split(user, ":")
		uid   string
		gid   string
	)

	switch len(parts) {
	case 1:
		uid = parts[0]
		gid = uid

	case 2:
		uid = parts[0]
		gid = parts[1]

	default:
		return fmt.Errorf("invalid user flag: %q", user)
	}

	_, err := strconv.ParseUint(uid, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid UID: %q", uid)
	}

	_, err = strconv.ParseUint(gid, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid GID: %q", gid)
	}

	return nil
}

func uidPtr(user string) *int64 {
	if user == "" {
		return nil
	}

	parts := strings.Split(user, ":")
	uid, _ := strconv.ParseInt(parts[0], 10, 32)
	return &uid
}

func gidPtr(user string) *int64 {
	if user == "" {
		return nil
	}

	if !strings.Contains(user, ":") {
		return uidPtr(user)
	}

	parts := strings.Split(user, ":")
	gid, _ := strconv.ParseInt(parts[1], 10, 32)
	return &gid
}
