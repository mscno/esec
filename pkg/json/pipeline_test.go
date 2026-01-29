package json

import (
	"errors"
	"sync"
	"testing"
)

func TestPipelineBasicAppendBytes(t *testing.T) {
	pl := newPipeline()

	pl.appendBytes([]byte("hello"))
	pl.appendBytes([]byte(" "))
	pl.appendBytes([]byte("world"))

	result, err := pl.flush()
	if err != nil {
		t.Errorf("flush() unexpected error = %v", err)
	}

	expected := "hello world"
	if string(result) != expected {
		t.Errorf("flush() = %q, want %q", string(result), expected)
	}
}

func TestPipelineAppendByte(t *testing.T) {
	pl := newPipeline()

	pl.appendByte('a')
	pl.appendByte('b')
	pl.appendByte('c')

	result, err := pl.flush()
	if err != nil {
		t.Errorf("flush() unexpected error = %v", err)
	}

	expected := "abc"
	if string(result) != expected {
		t.Errorf("flush() = %q, want %q", string(result), expected)
	}
}

func TestPipelineMixedBytesAndByte(t *testing.T) {
	pl := newPipeline()

	pl.appendBytes([]byte("hello"))
	pl.appendByte(',')
	pl.appendBytes([]byte("world"))

	result, err := pl.flush()
	if err != nil {
		t.Errorf("flush() unexpected error = %v", err)
	}

	expected := "hello,world"
	if string(result) != expected {
		t.Errorf("flush() = %q, want %q", string(result), expected)
	}
}

func TestPipelinePromise(t *testing.T) {
	pl := newPipeline()

	// Create a promise channel
	promise := make(chan promiseResult, 1)

	pl.appendBytes([]byte("start-"))
	pl.appendPromise(promise)
	pl.appendBytes([]byte("-end"))

	// Send the promise result
	promise <- promiseResult{bytes: []byte("middle")}

	result, err := pl.flush()
	if err != nil {
		t.Errorf("flush() unexpected error = %v", err)
	}

	expected := "start-middle-end"
	if string(result) != expected {
		t.Errorf("flush() = %q, want %q", string(result), expected)
	}
}

func TestPipelinePromiseWithError(t *testing.T) {
	pl := newPipeline()

	promise := make(chan promiseResult, 1)

	pl.appendBytes([]byte("start"))
	pl.appendPromise(promise)

	testErr := errors.New("test error")
	promise <- promiseResult{err: testErr}

	_, err := pl.flush()
	if err == nil {
		t.Error("flush() expected error, got nil")
	}
	if err != testErr {
		t.Errorf("flush() error = %v, want %v", err, testErr)
	}
}

func TestPipelineMultiplePromises(t *testing.T) {
	pl := newPipeline()

	promise1 := make(chan promiseResult, 1)
	promise2 := make(chan promiseResult, 1)
	promise3 := make(chan promiseResult, 1)

	pl.appendBytes([]byte("["))
	pl.appendPromise(promise1)
	pl.appendBytes([]byte(","))
	pl.appendPromise(promise2)
	pl.appendBytes([]byte(","))
	pl.appendPromise(promise3)
	pl.appendBytes([]byte("]"))

	// Send results in order
	promise1 <- promiseResult{bytes: []byte("1")}
	promise2 <- promiseResult{bytes: []byte("2")}
	promise3 <- promiseResult{bytes: []byte("3")}

	result, err := pl.flush()
	if err != nil {
		t.Errorf("flush() unexpected error = %v", err)
	}

	expected := "[1,2,3]"
	if string(result) != expected {
		t.Errorf("flush() = %q, want %q", string(result), expected)
	}
}

func TestPipelinePromisesMaintainOrder(t *testing.T) {
	pl := newPipeline()

	promise1 := make(chan promiseResult, 1)
	promise2 := make(chan promiseResult, 1)

	pl.appendPromise(promise1)
	pl.appendPromise(promise2)

	// Send results out of order (promise2 first)
	// But the pipeline should maintain order based on when appendPromise was called
	go func() {
		promise2 <- promiseResult{bytes: []byte("second")}
	}()
	go func() {
		promise1 <- promiseResult{bytes: []byte("first")}
	}()

	result, err := pl.flush()
	if err != nil {
		t.Errorf("flush() unexpected error = %v", err)
	}

	expected := "firstsecond"
	if string(result) != expected {
		t.Errorf("flush() = %q, want %q", string(result), expected)
	}
}

func TestPipelineEmptyFlush(t *testing.T) {
	pl := newPipeline()

	result, err := pl.flush()
	if err != nil {
		t.Errorf("flush() unexpected error = %v", err)
	}

	if len(result) != 0 {
		t.Errorf("flush() = %q, want empty", string(result))
	}
}

func TestPipelineConcurrentPromises(t *testing.T) {
	pl := newPipeline()

	numPromises := 100
	promises := make([]chan promiseResult, numPromises)

	for i := 0; i < numPromises; i++ {
		promises[i] = make(chan promiseResult, 1)
		pl.appendPromise(promises[i])
	}

	// Resolve promises concurrently in random order
	var wg sync.WaitGroup
	for i := 0; i < numPromises; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			promises[idx] <- promiseResult{bytes: []byte("x")}
		}(i)
	}

	wg.Wait()

	result, err := pl.flush()
	if err != nil {
		t.Errorf("flush() unexpected error = %v", err)
	}

	// All promises should have been processed
	if len(result) != numPromises {
		t.Errorf("flush() returned %d bytes, want %d", len(result), numPromises)
	}
}

func TestPipelineFlushPendingBytes(t *testing.T) {
	pl := newPipeline()

	// This tests the internal flushPendingBytes behavior
	pl.appendBytes([]byte("pending"))

	// Add a promise, which should flush pending bytes first
	promise := make(chan promiseResult, 1)
	pl.appendPromise(promise)
	promise <- promiseResult{bytes: []byte("-resolved")}

	pl.appendBytes([]byte("-more"))

	result, err := pl.flush()
	if err != nil {
		t.Errorf("flush() unexpected error = %v", err)
	}

	expected := "pending-resolved-more"
	if string(result) != expected {
		t.Errorf("flush() = %q, want %q", string(result), expected)
	}
}

func TestPipelineLargeData(t *testing.T) {
	pl := newPipeline()

	// Create a large byte slice
	largeData := make([]byte, 1024*1024) // 1MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	pl.appendBytes(largeData)

	result, err := pl.flush()
	if err != nil {
		t.Errorf("flush() unexpected error = %v", err)
	}

	if len(result) != len(largeData) {
		t.Errorf("flush() returned %d bytes, want %d", len(result), len(largeData))
	}

	// Verify data integrity
	for i := range result {
		if result[i] != largeData[i] {
			t.Errorf("data mismatch at index %d: got %d, want %d", i, result[i], largeData[i])
			break
		}
	}
}
