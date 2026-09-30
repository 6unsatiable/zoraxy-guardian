package guardian

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

const (
	maxBlockLog     = 2000            // in-memory snapshot cap
	syncInterval    = time.Second     // how often appended lines are fsync'd
	rotateAtSize    = 5 * 1024 * 1024 // 5 MiB
	rotateKeepLines = 2000            // lines kept on rotate
)

// blockLog is an append-only JSONL writer backed by a bounded in-memory
// ring. On open it tail-reads the file to repopulate the ring so the UI
// keeps its history across restarts. Appends are fsync'd once a second in the
// background: a per-line fsync under a scanner flood (thousands of blocks a
// second) turned every block into a disk write while holding the log lock.
// On size threshold the file is rotated in place by keeping the most recent
// N lines.
type blockLog struct {
	path string
	cap  int

	mu    sync.Mutex
	ring  []BlockLogEntry
	file  *os.File
	dirty bool
}

func openBlockLog(path string, capLines int) (*blockLog, error) {
	bl := &blockLog{path: path, cap: capLines}
	if err := bl.loadTail(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	bl.file = f
	go bl.syncLoop()
	return bl, nil
}

func (bl *blockLog) syncLoop() {
	t := time.NewTicker(syncInterval)
	defer t.Stop()
	for range t.C {
		bl.Flush()
	}
}

// Flush fsyncs lines appended since the last flush.
func (bl *blockLog) Flush() {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	if bl.dirty && bl.file != nil {
		_ = bl.file.Sync()
		bl.dirty = false
	}
}

func (bl *blockLog) loadTail() error {
	f, err := os.Open(bl.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	ring := make([]BlockLogEntry, 0, bl.cap)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e BlockLogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		ring = append(ring, e)
		if len(ring) > bl.cap {
			ring = ring[len(ring)-bl.cap:]
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return err
	}
	bl.ring = ring
	return nil
}

func (bl *blockLog) Append(entry BlockLogEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.ring = append(bl.ring, entry)
	if len(bl.ring) > bl.cap {
		bl.ring = bl.ring[len(bl.ring)-bl.cap:]
	}
	if bl.file != nil {
		data = append(data, '\n')
		if _, err := bl.file.Write(data); err == nil {
			bl.dirty = true
		}
		bl.rotateIfNeededLocked()
	}
}

func (bl *blockLog) Snapshot() []BlockLogEntry {
	bl.mu.Lock()
	defer bl.mu.Unlock()
	out := make([]BlockLogEntry, len(bl.ring))
	copy(out, bl.ring)
	return out
}

// rotateIfNeededLocked truncates the underlying file to its tail when it
// grows past rotateAtSize. Caller must hold bl.mu.
func (bl *blockLog) rotateIfNeededLocked() {
	if bl.file == nil {
		return
	}
	st, err := bl.file.Stat()
	if err != nil || st.Size() < rotateAtSize {
		return
	}

	start := 0
	if len(bl.ring) > rotateKeepLines {
		start = len(bl.ring) - rotateKeepLines
	}
	tmp := bl.path + ".tmp"
	w, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	bw := bufio.NewWriter(w)
	for i := start; i < len(bl.ring); i++ {
		data, err := json.Marshal(bl.ring[i])
		if err != nil {
			continue
		}
		bw.Write(data)
		bw.WriteByte('\n')
	}
	if err := bw.Flush(); err != nil {
		w.Close()
		os.Remove(tmp)
		return
	}
	if err := w.Sync(); err != nil {
		w.Close()
		os.Remove(tmp)
		return
	}
	if err := w.Close(); err != nil {
		os.Remove(tmp)
		return
	}
	bl.file.Close()
	if err := os.Rename(tmp, bl.path); err != nil {
		os.Remove(tmp)
		bl.file, _ = os.OpenFile(bl.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		return
	}
	bl.file, _ = os.OpenFile(bl.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
}
