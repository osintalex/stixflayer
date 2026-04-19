package stixflayer

import (
	"context"
	"testing"
)

func TestDomainObjectBuilder(t *testing.T) {
	plugin, err := NewPlugin("../../wasm-plugin/target/wasm32-wasip1/release/stix_wasm_plugin.wasm")
	if err != nil {
		t.Skipf("Wasm plugin not built yet: %v", err)
	}
	defer plugin.Close(context.Background())

	result, err := NewDomainObjectBuilder(plugin, "attack_pattern").
		Name("Spear Phishing").
		Description("Phishing attack via spear email").
		Build(context.Background())

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if result["type"] != "attack-pattern" {
		t.Errorf("Expected type 'attack-pattern', got %v", result["type"])
	}
	if result["name"] != "Spear Phishing" {
		t.Errorf("Expected name 'Spear Phishing', got %v", result["name"])
	}
	if result["description"] != "Phishing attack via spear email" {
		t.Errorf("Expected description, got %v", result["description"])
	}

	t.Logf("Result: %+v", result)
}
