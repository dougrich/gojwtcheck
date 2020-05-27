package gojwtcheck

import (
	"fmt"
)

type NestedError struct {
	message string
	inner   error
}

func (o NestedError) Error() string {
	return fmt.Sprintf("%s: %s", o.message, o.inner)
}
