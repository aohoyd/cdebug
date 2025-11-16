package kubernetes

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"

	"k8s.io/client-go/rest"

	"github.com/aohoyd/cdebug/pkg/kubernetes/types"
)

// Client is a minimal Kubernetes REST client
type Client struct {
	restConfig *rest.Config
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a new Kubernetes REST client
func NewClient(config *rest.Config) (*Client, error) {
	httpClient, err := rest.HTTPClientFor(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	baseURL := config.Host

	return &Client{
		restConfig: config,
		httpClient: httpClient,
		baseURL:    baseURL,
	}, nil
}

// buildURL constructs a URL for the Kubernetes API
func (c *Client) buildURL(pathSegments ...string) string {
	u, _ := url.Parse(c.baseURL)
	u.Path = path.Join(append([]string{"/api/v1"}, pathSegments...)...)
	return u.String()
}

// do executes an HTTP request
func (c *Client) do(ctx context.Context, method, url string, body io.Reader, result any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

// GetPod retrieves a pod by namespace and name
func (c *Client) GetPod(ctx context.Context, namespace, name string) (*types.Pod, error) {
	url := c.buildURL("namespaces", namespace, "pods", name)

	var pod types.Pod
	if err := c.do(ctx, http.MethodGet, url, nil, &pod); err != nil {
		return nil, err
	}

	return &pod, nil
}

// CreatePod creates a new pod
func (c *Client) CreatePod(ctx context.Context, namespace string, pod *types.Pod) (*types.Pod, error) {
	url := c.buildURL("namespaces", namespace, "pods")

	body, err := json.Marshal(pod)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pod: %w", err)
	}

	var result types.Pod
	if err := c.do(ctx, http.MethodPost, url, bytes.NewReader(body), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// PatchPod patches a pod using JSON Merge Patch
func (c *Client) PatchPod(ctx context.Context, namespace, name, subresource string, patchData []byte) (*types.Pod, error) {
	urlPath := []string{"namespaces", namespace, "pods", name}
	if subresource != "" {
		urlPath = append(urlPath, subresource)
	}
	url := c.buildURL(urlPath...)

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(patchData))
	if err != nil {
		return nil, fmt.Errorf("failed to create patch request: %w", err)
	}

	req.Header.Set("Content-Type", "application/merge-patch+json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute patch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("patch failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result types.Pod
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// WatchOptions contains options for watching resources
type WatchOptions struct {
	FieldSelector string
	Timeout       int64
}

// PodWatcher watches changes for pod
type PodWatcher struct {
	ctx    context.Context
	cancel context.CancelFunc
	events chan types.PodEvent
	errors chan error
}

// ResultChan returns the event channel
func (w *PodWatcher) ResultChan() <-chan types.PodEvent {
	return w.events
}

// Stop stops the watcher
func (w *PodWatcher) Stop() {
	w.cancel()
}

// WatchPods watches pods in a namespace
func (c *Client) WatchPods(ctx context.Context, namespace string, opts WatchOptions) (*PodWatcher, error) {
	u, _ := url.Parse(c.buildURL("namespaces", namespace, "pods"))
	q := u.Query()
	q.Set("watch", "true")
	if opts.FieldSelector != "" {
		q.Set("fieldSelector", opts.FieldSelector)
	}
	if opts.Timeout > 0 {
		q.Set("timeoutSeconds", fmt.Sprintf("%d", opts.Timeout))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create watch request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to start watch: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("watch failed with status %d", resp.StatusCode)
	}

	watchCtx, cancel := context.WithCancel(ctx)
	w := &PodWatcher{
		ctx:    watchCtx,
		cancel: cancel,
		events: make(chan types.PodEvent),
		errors: make(chan error, 1),
	}

	go func() {
		defer resp.Body.Close()
		defer close(w.events)
		defer close(w.errors)

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			select {
			case <-watchCtx.Done():
				return
			default:
			}

			var event types.PodEvent
			line := scanner.Bytes()

			// Parse watch event
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(line, &raw); err != nil {
				w.errors <- fmt.Errorf("failed to decode watch event: %w", err)
				return
			}

			var eventType string
			if err := json.Unmarshal(raw["type"], &eventType); err != nil {
				w.errors <- fmt.Errorf("failed to decode event type: %w", err)
				return
			}

			var pod types.Pod
			if err := json.Unmarshal(raw["object"], &pod); err != nil {
				w.errors <- fmt.Errorf("failed to decode pod: %w", err)
				return
			}

			event.Type = types.PodEventType(eventType)
			event.Pod = &pod

			select {
			case w.events <- event:
			case <-watchCtx.Done():
				return
			}
		}

		if err := scanner.Err(); err != nil {
			w.errors <- fmt.Errorf("watch scanner error: %w", err)
		}
	}()

	return w, nil
}

// PodLogOptions contains options for getting pod logs
type PodLogOptions struct {
	Container string
	Follow    bool
}

// GetPodLogs gets logs from a pod container
func (c *Client) GetPodLogs(ctx context.Context, namespace, name string, opts PodLogOptions) (io.ReadCloser, error) {
	u, _ := url.Parse(c.buildURL("namespaces", namespace, "pods", name, "log"))
	q := u.Query()
	if opts.Container != "" {
		q.Set("container", opts.Container)
	}
	if opts.Follow {
		q.Set("follow", "true")
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create logs request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("logs request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return resp.Body, nil
}

// RESTClient returns the underlying REST config (needed for remotecommand)
func (c *Client) RESTClient() *rest.Config {
	return c.restConfig
}
