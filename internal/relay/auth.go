package relay

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type credentialsStore struct {
	values map[string]string
}

func loadCredentials(path string) (*credentialsStore, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open credentials file: %w", err)
	}
	defer file.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid credentials format at line %d", line)
		}
		username := strings.TrimSpace(parts[0])
		password := strings.TrimSpace(parts[1])
		if username == "" || password == "" {
			return nil, fmt.Errorf("invalid credentials format at line %d", line)
		}
		values[username] = password
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read credentials file: %w", err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("credentials file has no entries")
	}
	return &credentialsStore{values: values}, nil
}

func (s *credentialsStore) check(username, password string) bool {
	if s == nil {
		return false
	}
	expected, ok := s.values[username]
	return ok && expected == password
}
