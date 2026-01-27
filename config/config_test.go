package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewConfig(t *testing.T) {
	// 1. Setup temporary directory
	tempDir := t.TempDir()

	// 2. Define a sample valid configuration content usage for verification

	// We need to match the schema requirements.
	// Let's create a minimal valid JSON string first to ensure we adhere to schema.json

	// Based on typical usage, let's construct a raw JSON that we know is valid
	// and serves as our source of truth.
	jsonContent := `{
  "tasks": {
    "my_task": {
      "filter": [
        {
          "ip": {
            "prefix": "2001:db8::/64"
          },
          "mac": {
            "address": "00:11:22:33:44:55"
          }
        }
      ],
      "endpoints": {
        "my_credential": [
          "sub.domain.com"
        ]
      }
    }
  },
  "credentials": {
    "my_credential": {
      "provider": "cloudflare",
      "debounce_time": "1s",
      "settings": {
        "api_token": "1234567890"
      }
    }
  }
}`

	yamlContent := `
tasks:
  my_task:
    filter:
      - ip:
          prefix: "2001:db8::/64"
        mac:
          address: "00:11:22:33:44:55"
    endpoints:
      my_credential:
        - sub.domain.com
credentials:
  my_credential:
    provider: cloudflare
    debounce_time: 1s
    settings:
      api_token: "1234567890"
`

	t.Run("Load JSON Config", func(t *testing.T) {
		jsonPath := filepath.Join(tempDir, "config.json")
		err := os.WriteFile(jsonPath, []byte(jsonContent), 0644)
		if err != nil {
			t.Fatalf("Failed to write json config: %v", err)
		}

		loadedConfig, err := NewConfig(jsonPath)
		if err != nil {
			t.Fatalf("NewConfig failed for JSON: %v", err)
		}

		if len(loadedConfig.Tasks) != 1 {
			t.Errorf("Expected 1 task, got %d", len(loadedConfig.Tasks))
		}
	})

	t.Run("Load YAML Config", func(t *testing.T) {
		yamlPath := filepath.Join(tempDir, "config.yaml")
		err := os.WriteFile(yamlPath, []byte(yamlContent), 0644)
		if err != nil {
			t.Fatalf("Failed to write yaml config: %v", err)
		}

		loadedConfig, err := NewConfig(yamlPath)
		if err != nil {
			t.Fatalf("NewConfig failed for YAML: %v", err)
		}

		if len(loadedConfig.Tasks) != 1 {
			t.Errorf("Expected 1 task, got %d", len(loadedConfig.Tasks))
		}

		if _, ok := loadedConfig.Tasks["my_task"]; !ok {
			t.Error("Expected 'my_task' to exist")
		}
	})

	t.Run("Load Config Plugins Map", func(t *testing.T) {
		yamlContent := `
tasks: {}
credentials: {}
discovery:
  plugins:
    mikrotik-lan:
      type: mikrotik
      params: param1
`
		path := filepath.Join(tempDir, "config_plugins.yaml")
		_ = os.WriteFile(path, []byte(yamlContent), 0644)

		cfg, err := NewConfig(path)
		if err != nil {
			t.Fatalf("NewConfig failed: %v", err)
		}

		if len(cfg.Discovery.Plugins) != 1 {
			t.Errorf("Expected 1 plugin, got %d", len(cfg.Discovery.Plugins))
		}
		if _, ok := cfg.Discovery.Plugins["mikrotik-lan"]; !ok {
			t.Error("Expected plugin 'mikrotik-lan'")
		}
	})

	t.Run("Load Config Nested Filters", func(t *testing.T) {
		yamlContent := `
tasks:
  new_task:
    filter:
      - mac:
          address: "00:11:22:33:44:66"
        ip:
          type: ["global", "eui64"]
        source: ["mikrotik-lan"]
    endpoints:
      creds: ["host"]
credentials:
  creds:
    provider: test
    settings: {}
`
		path := filepath.Join(tempDir, "config_filters.yaml")
		_ = os.WriteFile(path, []byte(yamlContent), 0644)

		cfg, err := NewConfig(path)
		if err != nil {
			t.Fatalf("NewConfig failed: %v", err)
		}

		// Check filters
		task := cfg.Tasks["new_task"]
		if len(task.Filters) == 0 {
			t.Fatal("No filters found")
		}
		f := task.Filters[0]
		if f.MAC.Address != "00:11:22:33:44:66" {
			t.Error("Filter MAC mismatch")
		}
		if len(f.IP.Type) != 2 {
			t.Error("Filter IPType mismatch")
		}
		if len(f.Source) != 1 || f.Source[0] != "mikrotik-lan" {
			t.Error("Filter Source mismatch")
		}
	})
}
