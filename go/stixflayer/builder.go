package stixflayer

import (
	"context"
	"encoding/json"

	extism "github.com/extism/go-sdk"
)

type DomainObjectBuilder struct {
	objectType string
	properties map[string]interface{}
	plugin     *extism.Plugin
}

func NewDomainObjectBuilder(plugin *extism.Plugin, objectType string) *DomainObjectBuilder {
	return &DomainObjectBuilder{
		objectType: objectType,
		properties: make(map[string]interface{}),
		plugin:     plugin,
	}
}

func (b *DomainObjectBuilder) Name(name string) *DomainObjectBuilder {
	b.properties["name"] = name
	return b
}

func (b *DomainObjectBuilder) Description(desc string) *DomainObjectBuilder {
	b.properties["description"] = desc
	return b
}

func (b *DomainObjectBuilder) Aliases(aliases []string) *DomainObjectBuilder {
	b.properties["aliases"] = aliases
	return b
}

func (b *DomainObjectBuilder) Build(ctx context.Context) (map[string]interface{}, error) {
	inputJSON, err := json.Marshal(b.properties)
	if err != nil {
		return nil, err
	}

	_, output, err := b.plugin.Call(b.objectType, inputJSON)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, err
	}

	return result, nil
}

func (b *DomainObjectBuilder) JSON(ctx context.Context) ([]byte, error) {
	result, err := b.Build(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
