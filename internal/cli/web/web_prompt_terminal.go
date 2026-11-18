package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// When asc runs without a terminal (an agent, a script, an editor task) it can
// still ask a person for the Apple Account password or a 2FA code: it opens a
// Herdr tab or a tmux window that shows the prompt, and reads the answer back
// from a private temporary file. ASC_WEB_PROMPT_TERMINAL picks the terminal.
const webPromptTerminalEnv = "ASC_WEB_PROMPT_TERMINAL"

type promptTerminal string

const (
	promptTerminalOff   promptTerminal = "off"
	promptTerminalHerdr promptTerminal = "herdr"
	promptTerminalTmux  promptTerminal = "tmux"
)

var (
	promptTerminalLookPathFn = exec.LookPath
	promptTerminalOutputFn   = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		out, err := exec.CommandContext(ctx, name, args...).Output()
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(strings.TrimSpace(string(exitErr.Stderr))) > 0 {
			return out, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return out, err
	}
	promptTerminalStatusWriter io.Writer = os.Stderr
	promptTerminalTimeout                = 10 * time.Minute
	promptTerminalPollInterval           = 250 * time.Millisecond
)

// resolvePromptTerminal returns the terminal a prompt opens in when asc has no
// terminal of its own. "auto" (the default) prefers the tmux session asc runs
// in, then a running Herdr server, then a detached tmux session.
func resolvePromptTerminal() (promptTerminal, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(webPromptTerminalEnv)))
	switch mode {
	case "", "auto":
	case string(promptTerminalOff), "none", "0", "false":
		return promptTerminalOff, nil
	case string(promptTerminalHerdr), string(promptTerminalTmux):
		if _, err := promptTerminalLookPathFn(mode); err != nil {
			return promptTerminalOff, fmt.Errorf("%s=%s but %s is not installed", webPromptTerminalEnv, mode, mode)
		}
		return promptTerminal(mode), nil
	default:
		return promptTerminalOff, fmt.Errorf("%s must be auto, herdr, tmux or off, got %q", webPromptTerminalEnv, mode)
	}

	_, tmuxErr := promptTerminalLookPathFn("tmux")
	if tmuxErr == nil && os.Getenv("TMUX") != "" {
		return promptTerminalTmux, nil
	}
	if herdrServerRunning() {
		return promptTerminalHerdr, nil
	}
	if tmuxErr == nil {
		return promptTerminalTmux, nil
	}
	return promptTerminalOff, nil
}

func herdrServerRunning() bool {
	if _, err := promptTerminalLookPathFn("herdr"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := promptTerminalOutputFn(ctx, "herdr", "status", "server")
	return err == nil && strings.Contains(string(out), "status: running")
}

// promptTerminalAvailable reports whether a prompt can open in Herdr or tmux.
func promptTerminalAvailable() bool {
	terminal, err := resolvePromptTerminal()
	return err == nil && terminal != promptTerminalOff
}

// twoFactorPromptAvailable reports whether a 2FA code can be asked for here:
// in asc's own terminal, or in a Herdr tab or tmux window.
func twoFactorPromptAvailable() bool {
	return terminalPromptAvailable() || promptTerminalAvailable()
}

// promptInTerminal shows prompt in a new Herdr tab or tmux window and returns
// what the person typed. Input is not echoed. The answer travels through a
// file in a temporary directory only this user can read, removed on return.
func promptInTerminal(ctx context.Context, title, prompt string) (string, error) {
	terminal, err := resolvePromptTerminal()
	if err != nil {
		return "", err
	}
	if terminal == promptTerminalOff {
		return "", errNoPromptTerminal
	}

	dir, err := os.MkdirTemp("", "asc-prompt-")
	if err != nil {
		return "", fmt.Errorf("prompt terminal: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("prompt terminal: %w", err)
	}
	answerPath := filepath.Join(dir, "answer")
	scriptPath := filepath.Join(dir, "prompt.sh")
	if err := os.WriteFile(scriptPath, []byte(promptTerminalScript(prompt, answerPath)), 0o700); err != nil {
		return "", fmt.Errorf("prompt terminal: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, promptTerminalTimeout)
	defer cancel()

	var pane promptPane
	switch terminal {
	case promptTerminalHerdr:
		pane, err = openHerdrPromptPane(ctx, title, dir, scriptPath)
	case promptTerminalTmux:
		pane, err = openTmuxPromptPane(ctx, title, scriptPath)
	}
	if err != nil {
		return "", err
	}
	defer pane.close()
	_, _ = fmt.Fprintln(promptTerminalStatusWriter, pane.notice)

	ticker := time.NewTicker(promptTerminalPollInterval)
	defer ticker.Stop()
	for {
		if data, readErr := os.ReadFile(answerPath); readErr == nil {
			answer := strings.TrimSpace(string(data))
			if answer == "" {
				return "", fmt.Errorf("%s: empty answer", title)
			}
			return answer, nil
		}
		if !pane.alive() {
			// The script exits right after writing, which can close the pane
			// between the read above and this check.
			if data, readErr := os.ReadFile(answerPath); readErr == nil && strings.TrimSpace(string(data)) != "" {
				return strings.TrimSpace(string(data)), nil
			}
			return "", fmt.Errorf("%s: the prompt was closed without an answer", title)
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("%s: no answer in the prompt terminal: %w", title, ctx.Err())
		case <-ticker.C:
		}
	}
}

var errNoPromptTerminal = errors.New("no terminal for a prompt: run in a terminal, or install Herdr or tmux (" + webPromptTerminalEnv + ")")

// promptTerminalScript reads one line without echo and writes it atomically,
// so asc never reads half an answer.
func promptTerminalScript(prompt, answerPath string) string {
	return strings.Join([]string{
		"#!/bin/sh",
		"umask 077",
		"printf '%s' " + shellQuote(prompt),
		"stty -echo 2>/dev/null",
		"IFS= read -r answer",
		"stty echo 2>/dev/null",
		"echo",
		"printf '%s' \"$answer\" > " + shellQuote(answerPath+".tmp") + " && mv " + shellQuote(answerPath+".tmp") + " " + shellQuote(answerPath),
		"",
	}, "\n")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

type promptPane struct {
	notice string
	alive  func() bool
	close  func()
}

func openHerdrPromptPane(ctx context.Context, title, dir, scriptPath string) (promptPane, error) {
	out, err := promptTerminalOutputFn(ctx, "herdr", "tab", "create", "--label", title, "--cwd", dir, "--focus")
	if err != nil {
		return promptPane{}, fmt.Errorf("prompt terminal: herdr tab create: %w", err)
	}
	var created struct {
		Result struct {
			RootPane struct {
				PaneID string `json:"pane_id"`
			} `json:"root_pane"`
			Tab struct {
				TabID string `json:"tab_id"`
			} `json:"tab"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &created); err != nil || created.Result.RootPane.PaneID == "" || created.Result.Tab.TabID == "" {
		return promptPane{}, fmt.Errorf("prompt terminal: unexpected herdr tab create output")
	}
	paneID, tabID := created.Result.RootPane.PaneID, created.Result.Tab.TabID
	closeTab := func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = promptTerminalOutputFn(closeCtx, "herdr", "tab", "close", tabID)
	}
	if _, err := promptTerminalOutputFn(ctx, "herdr", "pane", "run", paneID, "sh "+shellQuote(scriptPath)+"; exit"); err != nil {
		closeTab()
		return promptPane{}, fmt.Errorf("prompt terminal: herdr pane run: %w", err)
	}
	return promptPane{
		notice: fmt.Sprintf("Waiting for %s in Herdr tab %q (pane %s). An agent can answer with: herdr pane send-text %s '<value>' && herdr pane send-keys %s Enter", title, title, paneID, paneID, paneID),
		alive: func() bool {
			aliveCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err := promptTerminalOutputFn(aliveCtx, "herdr", "tab", "get", tabID)
			return err == nil
		},
		close: closeTab,
	}, nil
}

func openTmuxPromptPane(ctx context.Context, title, scriptPath string) (promptPane, error) {
	command := "sh " + shellQuote(scriptPath)
	attach := ""
	var args []string
	if os.Getenv("TMUX") != "" {
		args = []string{"new-window", "-P", "-F", "#{pane_id}", "-n", title, command}
	} else {
		session := fmt.Sprintf("asc-prompt-%d", os.Getpid())
		args = []string{"new-session", "-d", "-P", "-F", "#{pane_id}", "-s", session, "-n", title, command}
		attach = fmt.Sprintf(" Attach with: tmux attach -t %s.", session)
	}
	out, err := promptTerminalOutputFn(ctx, "tmux", args...)
	if err != nil {
		return promptPane{}, fmt.Errorf("prompt terminal: tmux %s: %w", args[0], err)
	}
	paneID := strings.TrimSpace(string(out))
	if paneID == "" {
		return promptPane{}, fmt.Errorf("prompt terminal: unexpected tmux output")
	}
	return promptPane{
		notice: fmt.Sprintf("Waiting for %s in tmux pane %s.%s An agent can answer with: tmux send-keys -t %s '<value>' Enter", title, paneID, attach, paneID),
		alive: func() bool {
			aliveCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			out, err := promptTerminalOutputFn(aliveCtx, "tmux", "display-message", "-p", "-t", paneID, "#{pane_dead}")
			return err == nil && strings.TrimSpace(string(out)) != "1"
		},
		close: func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = promptTerminalOutputFn(closeCtx, "tmux", "kill-pane", "-t", paneID)
		},
	}, nil
}
