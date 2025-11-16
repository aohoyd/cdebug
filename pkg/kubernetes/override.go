package kubernetes

import (
	"encoding/json"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch"
)

type OverrideType string

const (
	// OverrideTypeJSON will use an RFC6902 JSON Patch to alter the generated output
	OverrideTypeJSON OverrideType = "json"

	// OverrideTypeMerge will use an RFC7396 JSON Merge Patch to alter the generated output
	OverrideTypeMerge OverrideType = "merge"
)

const DefaultOverrideType = OverrideTypeMerge

func Override[D any](dest D, fragment string, overrideType OverrideType) (o D, err error) {
	if len(overrideType) == 0 {
		overrideType = DefaultOverrideType
	}

	switch overrideType {
	case OverrideTypeJSON:
		return JSONPatch(dest, fragment)

	case OverrideTypeMerge:
		return MergePatch(dest, fragment)

	default:
		return o, fmt.Errorf("invalid override type: %v", overrideType)
	}
}

func MergePatch[D any](dest D, fragment string) (o D, err error) {
	target, err := json.Marshal(dest)
	if err != nil {
		return o, fmt.Errorf("failed to JSON marshal object: %w", err)
	}

	patched, err := jsonpatch.MergePatch(target, []byte(fragment))
	if err != nil {
		return o, fmt.Errorf("failed to merge patch object: %w", err)
	}

	if err := json.Unmarshal(patched, &o); err != nil {
		return o, fmt.Errorf("failed to unmarshal patched object: %w", err)
	}

	return o, nil
}

func JSONPatch[D any](dest D, fragment string) (o D, err error) {
	target, err := json.Marshal(dest)
	if err != nil {
		return o, fmt.Errorf("failed to JSON marshal object: %w", err)
	}

	patch, err := jsonpatch.DecodePatch([]byte(fragment))
	if err != nil {
		return o, fmt.Errorf("failed to decode JSON patch: %w", err)
	}
	patched, err := patch.Apply(target)
	if err != nil {
		return o, fmt.Errorf("failed to apply JSON patch: %w", err)
	}

	if err := json.Unmarshal(patched, &o); err != nil {
		return o, fmt.Errorf("failed to unmarshal patched object: %w", err)
	}

	return o, nil
}
