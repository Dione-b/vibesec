package plugin

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

type Executor struct {
	Timeout time.Duration
}

func NewExecutor(timeout time.Duration) *Executor {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &Executor{Timeout: timeout}
}

func (e *Executor) Available(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (e *Executor) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !e.Available(name) {
		return nil, fmt.Errorf("%s not found in PATH", name)
	}
	runCtx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s: %w", name, err)
	}
	return output, nil
}
