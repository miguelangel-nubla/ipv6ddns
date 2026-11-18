package config

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// expandSecrets replaces, in every string of the JSON configuration, ${NAME} with the environment
// variable NAME, and ${file:PATH} with the content of the file, without its final newlines. A
// relative PATH is from baseDir. $${ is a literal ${. So secrets can stay out of the file.
func expandSecrets(configData []byte, baseDir string) ([]byte, error) {
	var config any
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, err
	}
	expanded, err := expandValue(config, "", baseDir)
	if err != nil {
		return nil, err
	}
	return json.Marshal(expanded)
}

func expandValue(value any, path string, baseDir string) (any, error) {
	switch v := value.(type) {
	case string:
		expanded, err := expandString(v, baseDir)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", strings.TrimPrefix(path, "."), err)
		}
		return expanded, nil
	case map[string]any:
		for _, key := range slices.Sorted(maps.Keys(v)) {
			expanded, err := expandValue(v[key], path+"."+key, baseDir)
			if err != nil {
				return nil, err
			}
			v[key] = expanded
		}
		return v, nil
	case []any:
		for i := range v {
			expanded, err := expandValue(v[i], fmt.Sprintf("%s[%d]", path, i), baseDir)
			if err != nil {
				return nil, err
			}
			v[i] = expanded
		}
		return v, nil
	default:
		return v, nil
	}
}

func expandString(s string, baseDir string) (string, error) {
	var result strings.Builder
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			result.WriteString(s)
			return result.String(), nil
		}
		// $${ is a literal ${: the first $ is dropped.
		if i > 0 && s[i-1] == '$' {
			result.WriteString(s[:i-1])
			result.WriteString("${")
			s = s[i+2:]
			continue
		}
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return "", fmt.Errorf("an unterminated ${, write $${ for a literal one")
		}
		result.WriteString(s[:i])
		value, err := resolve(s[i+2:i+end], baseDir)
		if err != nil {
			return "", err
		}
		result.WriteString(value)
		s = s[i+end+1:]
	}
}

func resolve(reference string, baseDir string) (string, error) {
	if path, ok := strings.CutPrefix(reference, "file:"); ok {
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("reading the file of ${file:...}: %w", err)
		}
		return strings.TrimRight(string(content), "\r\n"), nil
	}
	if reference == "" {
		return "", fmt.Errorf("an empty ${}")
	}
	value, ok := os.LookupEnv(reference)
	if !ok {
		return "", fmt.Errorf("the environment variable %s is not set", reference)
	}
	return value, nil
}
