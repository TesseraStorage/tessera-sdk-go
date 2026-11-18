package siastorage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// AgentMetadataKey is the top-level key in an object's metadata JSON object
// that holds [AgentMetadata].
const AgentMetadataKey = "agent"

// ErrMetadataNotObject is returned by [Object.SetAgentMetadata] and
// [Object.AgentMetadata] when the object's existing metadata is not a JSON
// object, so agent metadata cannot be added without replacing it.
var ErrMetadataNotObject = errors.New("object metadata is not a JSON object")

// AgentMetadata records which agent wrote an object and why. It is stored
// under [AgentMetadataKey] in the object's metadata, which is encrypted with
// the rest of the metadata when the object is sealed. The indexer never sees
// it in plaintext.
type AgentMetadata struct {
	// Name identifies the agent that wrote the object.
	Name string `json:"name,omitempty"`
	// Run identifies the agent run or session that wrote the object.
	Run string `json:"run,omitempty"`
	// Task describes what the agent was doing when it wrote the object.
	Task string `json:"task,omitempty"`
	// Labels are free-form key/value pairs set by the agent.
	Labels map[string]string `json:"labels,omitempty"`
}

// metadataFields decodes the object's metadata as a JSON object. Empty or
// null metadata decodes to an empty map.
func (o *Object) metadataFields() (map[string]json.RawMessage, error) {
	fields := make(map[string]json.RawMessage)
	trimmed := bytes.TrimSpace(o.metadata)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fields, nil
	}
	if trimmed[0] != '{' {
		return nil, ErrMetadataNotObject
	}
	if err := json.Unmarshal(trimmed, &fields); err != nil {
		return nil, fmt.Errorf("failed to decode object metadata: %w", err)
	}
	return fields, nil
}

// AgentMetadata returns the agent metadata stored in the object's metadata.
// ok is false when none is stored.
func (o *Object) AgentMetadata() (meta AgentMetadata, ok bool, err error) {
	fields, err := o.metadataFields()
	if err != nil {
		return AgentMetadata{}, false, err
	}
	raw, ok := fields[AgentMetadataKey]
	if !ok {
		return AgentMetadata{}, false, nil
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return AgentMetadata{}, false, fmt.Errorf("failed to decode agent metadata: %w", err)
	}
	return meta, true, nil
}

// SetAgentMetadata stores meta under [AgentMetadataKey] in the object's
// metadata. Every other top-level key is kept with its value unchanged.
// Empty metadata becomes a JSON object holding only the agent metadata.
// Metadata that is not a JSON object is left unchanged and
// [ErrMetadataNotObject] is returned.
//
// The change is local. Call [SDK.PinObject] to save it on the indexer.
func (o *Object) SetAgentMetadata(meta AgentMetadata) error {
	fields, err := o.metadataFields()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to encode agent metadata: %w", err)
	}
	fields[AgentMetadataKey] = raw
	buf, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("failed to encode object metadata: %w", err)
	}
	o.metadata = buf
	return nil
}
