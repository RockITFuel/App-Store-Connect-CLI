package web

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func stubPromptTerminal(t *testing.T, installed map[string]bool, output func(ctx context.Context, name string, args ...string) ([]byte, error)) {
	t.Helper()
	prevLook, prevOut, prevWriter, prevPoll := promptTerminalLookPathFn, promptTerminalOutputFn, promptTerminalStatusWriter, promptTerminalPollInterval
	promptTerminalLookPathFn = func(name string) (string, error) {
		if installed[name] {
			return "/usr/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	}
	promptTerminalOutputFn = output
	promptTerminalStatusWriter = io.Discard
	promptTerminalPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		promptTerminalLookPathFn, promptTerminalOutputFn, promptTerminalStatusWriter, promptTerminalPollInterval = prevLook, prevOut, prevWriter, prevPoll
	})
}

func herdrStatus(running bool) func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "herdr" && strings.Join(args, " ") == "status server" {
			if running {
				return []byte("server:\n  status: running\n"), nil
			}
			return []byte("server:\n  status: stopped\n"), nil
		}
		return nil, errors.New("unexpected command")
	}
}

func TestResolvePromptTerminal(t *testing.T) {
	cases := []struct {
		name      string
		env       string
		tmuxEnv   string
		installed map[string]bool
		herdrUp   bool
		want      promptTerminal
		wantErr   bool
	}{
		{name: "auto prefers the tmux session asc runs in", tmuxEnv: "/tmp/tmux-1/default,1,0", installed: map[string]bool{"tmux": true, "herdr": true}, herdrUp: true, want: promptTerminalTmux},
		{name: "auto uses a running herdr server outside tmux", installed: map[string]bool{"tmux": true, "herdr": true}, herdrUp: true, want: promptTerminalHerdr},
		{name: "auto falls back to a detached tmux session", installed: map[string]bool{"tmux": true, "herdr": true}, herdrUp: false, want: promptTerminalTmux},
		{name: "auto without either is off", installed: map[string]bool{}, want: promptTerminalOff},
		{name: "off", env: "off", installed: map[string]bool{"tmux": true}, want: promptTerminalOff},
		{name: "explicit herdr", env: "herdr", installed: map[string]bool{"herdr": true}, want: promptTerminalHerdr},
		{name: "explicit tmux not installed", env: "tmux", installed: map[string]bool{}, wantErr: true},
		{name: "unknown value", env: "screen", installed: map[string]bool{"tmux": true}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(webPromptTerminalEnv, tc.env)
			t.Setenv("TMUX", tc.tmuxEnv)
			stubPromptTerminal(t, tc.installed, herdrStatus(tc.herdrUp))
			got, err := resolvePromptTerminal()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// runScriptLike runs the command a terminal would run, answering the prompt on stdin.
func runScriptLike(t *testing.T, command, answer string) {
	t.Helper()
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdin = strings.NewReader(answer + "\n")
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		t.Errorf("prompt script failed: %v", err)
	}
}

func TestPromptInTerminalTmuxReadsTheTypedAnswer(t *testing.T) {
	t.Setenv(webPromptTerminalEnv, "tmux")
	t.Setenv("TMUX", "")
	var wg sync.WaitGroup
	var mu sync.Mutex
	var calls []string
	stubPromptTerminal(t, map[string]bool{"tmux": true}, func(_ context.Context, name string, args ...string) ([]byte, error) {
		mu.Lock()
		calls = append(calls, name+" "+args[0])
		mu.Unlock()
		switch args[0] {
		case "new-session":
			command := args[len(args)-1]
			wg.Add(1)
			go func() { defer wg.Done(); runScriptLike(t, command, "123 456") }()
			return []byte("%42\n"), nil
		case "display-message":
			return []byte("0\n"), nil
		case "kill-pane":
			return nil, nil
		}
		return nil, errors.New("unexpected tmux command")
	})
	got, err := promptInTerminal(context.Background(), "Apple 2FA code", "Enter 2FA code: ")
	wg.Wait()
	if err != nil {
		t.Fatalf("promptInTerminal: %v", err)
	}
	if got != "123 456" {
		t.Fatalf("answer = %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls[len(calls)-1] != "tmux kill-pane" {
		t.Fatalf("pane not closed: %v", calls)
	}
}

func TestPromptInTerminalHerdrReadsTheTypedAnswerAfterThePaneCloses(t *testing.T) {
	t.Setenv(webPromptTerminalEnv, "herdr")
	var wg sync.WaitGroup
	done := make(chan struct{})
	var closed bool
	stubPromptTerminal(t, map[string]bool{"herdr": true}, func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch strings.Join(args[:2], " ") {
		case "tab create":
			return []byte(`{"id":"cli:tab:create","result":{"root_pane":{"pane_id":"w:p1"},"tab":{"tab_id":"w:t1"},"type":"tab_created"}}`), nil
		case "pane run":
			command := args[3]
			wg.Add(1)
			go func() { defer wg.Done(); runScriptLike(t, command, "pa'ss word"); close(done) }()
			return nil, nil
		case "tab get":
			select {
			case <-done:
				return nil, errors.New("tab not found")
			default:
				return []byte(`{}`), nil
			}
		case "tab close":
			closed = true
			return nil, nil
		}
		return nil, errors.New("unexpected herdr command")
	})
	got, err := promptInTerminal(context.Background(), "Apple Account password", "Password: ")
	wg.Wait()
	if err != nil {
		t.Fatalf("promptInTerminal: %v", err)
	}
	if got != "pa'ss word" {
		t.Fatalf("answer = %q", got)
	}
	if !closed {
		t.Fatal("herdr tab not closed")
	}
}

func TestPromptInTerminalFailsWhenThePromptIsClosed(t *testing.T) {
	t.Setenv(webPromptTerminalEnv, "tmux")
	t.Setenv("TMUX", "")
	stubPromptTerminal(t, map[string]bool{"tmux": true}, func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch args[0] {
		case "new-session":
			return []byte("%7\n"), nil
		case "display-message":
			return nil, errors.New("can't find pane")
		}
		return nil, nil
	})
	if _, err := promptInTerminal(context.Background(), "Apple 2FA code", "Code: "); err == nil || !strings.Contains(err.Error(), "closed without an answer") {
		t.Fatalf("err = %v", err)
	}
}

func TestPromptInTerminalOffReturnsNoTerminal(t *testing.T) {
	t.Setenv(webPromptTerminalEnv, "off")
	if _, err := promptInTerminal(context.Background(), "Apple 2FA code", "Code: "); !errors.Is(err, errNoPromptTerminal) {
		t.Fatalf("err = %v", err)
	}
}

// TestPromptInTerminalReal drives a real Herdr server or tmux: set
// ASC_E2E_PROMPT_TERMINAL=herdr or tmux, and ASC_E2E_HOME=$HOME, to run it.
func TestPromptInTerminalReal(t *testing.T) {
	terminal := os.Getenv("ASC_E2E_PROMPT_TERMINAL")
	if terminal != "herdr" && terminal != "tmux" {
		t.Skip("set ASC_E2E_PROMPT_TERMINAL=herdr or tmux to run against a real terminal")
	}
	t.Setenv(webPromptTerminalEnv, terminal)
	// TestMain points HOME at a temporary folder; Herdr and tmux find their sockets in the real one.
	if home := os.Getenv("ASC_E2E_HOME"); home != "" {
		t.Setenv("HOME", home)
	}
	prevWriter := promptTerminalStatusWriter
	reader, writer := io.Pipe()
	promptTerminalStatusWriter = writer
	t.Cleanup(func() { promptTerminalStatusWriter = prevWriter })
	go func() {
		buf := make([]byte, 4096)
		n, _ := reader.Read(buf)
		notice := string(buf[:n])
		time.Sleep(1500 * time.Millisecond)
		if terminal == "herdr" {
			start := strings.Index(notice, "(pane ")
			paneID := strings.TrimSuffix(strings.Fields(notice[start+len("(pane "):])[0], ").")
			_ = exec.Command("herdr", "pane", "send-text", paneID, "654321").Run()
			_ = exec.Command("herdr", "pane", "send-keys", paneID, "Enter").Run()
			return
		}
		start := strings.Index(notice, "tmux pane ")
		paneID := strings.TrimSuffix(strings.Fields(notice[start+len("tmux pane "):])[0], ".")
		_ = exec.Command("tmux", "send-keys", "-t", paneID, "654321", "Enter").Run()
	}()
	got, err := promptInTerminal(context.Background(), "asc e2e prompt", "Enter test code: ")
	if err != nil {
		t.Fatalf("promptInTerminal: %v", err)
	}
	if got != "654321" {
		t.Fatalf("answer = %q", got)
	}
}
