package stixflayer

import (
	"context"

	extism "github.com/extism/go-sdk"
)

func NewPlugin(wasmPath string) (*extism.Plugin, error) {
	manifest := extism.Manifest{
		Wasm: []extism.Wasm{
			extism.WasmFile{Path: wasmPath},
		},
	}

	ctx := context.Background()
	config := extism.PluginConfig{
		EnableWasi: true,
	}
	return extism.NewPlugin(ctx, manifest, config, nil)
}
