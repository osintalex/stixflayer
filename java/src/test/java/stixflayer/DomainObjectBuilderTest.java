package stixflayer;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import org.extism.sdk.Plugin;
import org.extism.sdk.manifest.Manifest;
import org.extism.sdk.wasm.FileWasmSource;

class DomainObjectBuilderTest {

    private static Plugin plugin;

    @BeforeAll
    static void setUp() throws Exception {
        Path wasmPath = Paths.get("..", "wasm-plugin", "target", "wasm32-wasip1", "release", "stix_wasm_plugin.wasm");
        if (!Files.exists(wasmPath)) {
            wasmPath = Paths.get("wasm-plugin", "target", "wasm32-wasip1", "release", "stix_wasm_plugin.wasm");
        }

        var wasm = FileWasmSource.fromPath(wasmPath).build();
        var manifest = Manifest.ofWasms(wasm).build();
        plugin = Plugin.ofManifest(manifest).build();
    }

    @Test
    void testAttackPattern() throws Exception {
        Map<String, Object> properties = new HashMap<>();
        properties.put("name", "Spear Phishing");

        String inputJson = new com.fasterxml.jackson.databind.ObjectMapper()
                .writeValueAsString(properties);

        byte[] inputBytes = inputJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        byte[] outputBytes = plugin.call("attack_pattern", inputBytes);

        String outputJson = new String(outputBytes, java.nio.charset.StandardCharsets.UTF_8);

        Map<String, Object> result = new com.fasterxml.jackson.databind.ObjectMapper()
                .readValue(outputJson, Map.class);

        assertThat(result).containsKey("type");
        assertThat(result.get("type")).isEqualTo("attack-pattern");
        assertThat(result).containsKey("id");
        assertThat(result).containsKey("created");
        assertThat(result).containsKey("modified");
    }
}