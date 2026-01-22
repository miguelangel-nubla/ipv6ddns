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
      "subnets": ["2001:db8::/64"],
      "mac_address": ["00:11:22:33:44:55"],
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
    subnets:
      - "2001:db8::/64"
    mac_address:
      - "00:11:22:33:44:55"
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
}
