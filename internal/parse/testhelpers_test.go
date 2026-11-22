package parse

import (
	"errors"
	"path"
)

var errNotFound = errors.New("not found")

func pathMatch(pattern, name string) (bool, error) { return path.Match(pattern, name) }
