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
// relative PATH is from baseDir. So secrets can stay out of the file.
//
// Right before a {, each pair of $ is one literal $, and an odd one left starts a ${: $${ is a
// literal ${, and $$${NAME} a $ before the variable, as a backslash escapes a backslash. A $
// anywhere else is as written, as the two of pa$$word, which the escape doesn't take.
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
		// The $ before this one, of the same run: each pair is one $.
		start := i
		for start > 0 && s[start-1] == '$' {
			start--
		}
		result.WriteString(s[:start])
		dollars := i - start + 1
		result.WriteString(strings.Repeat("$", dollars/2))
		if dollars%2 == 0 {
			// A literal {, after them.
			result.WriteByte('{')
			s = s[i+2:]
			continue
		}
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return "", fmt.Errorf("an unclosed ${: write $${ for a literal one")
		}
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
