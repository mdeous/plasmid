package saml

import (
	"sync"
	"sync/atomic"
	"time"
)

type Attribute struct {
	Name   string
	Values []string
}

type SAMLExchange struct {
	ID              string
	Timestamp       string
	Direction       string
	Endpoint        string
	ServiceProvider string
	NameID          string
	RelayState      string
	Signed          bool
	AssertionSigned bool
	Tampered        bool
	Modifications   []TamperModification
	Attributes      []Attribute
	RawXML          string
	RemoteAddr      string
}

type Inspector struct {
	mu       sync.RWMutex
	buffer   []SAMLExchange
	capacity int
	nextID   atomic.Int64
}

func NewInspector(capacity int) *Inspector {
	if capacity <= 0 {
		capacity = 100
	}
	return &Inspector{
		buffer:   make([]SAMLExchange, 0, capacity),
		capacity: capacity,
	}
}

func (i *Inspector) Record(exchange SAMLExchange) {
	i.mu.Lock()
	defer i.mu.Unlock()

	id := i.nextID.Add(1)
	exchange.ID = time.Now().Format("20060102-150405") + "-" + itoa(id)
	if exchange.Timestamp == "" {
		exchange.Timestamp = time.Now().Format("2006-01-02 15:04:05")
	}

	if len(i.buffer) >= i.capacity {
		copy(i.buffer, i.buffer[1:])
		i.buffer = i.buffer[:len(i.buffer)-1]
	}
	i.buffer = append(i.buffer, exchange)
}

func (i *Inspector) List() []SAMLExchange {
	i.mu.RLock()
	defer i.mu.RUnlock()

	result := make([]SAMLExchange, len(i.buffer))
	for j, ex := range i.buffer {
		result[len(i.buffer)-1-j] = ex
	}
	return result
}

func (i *Inspector) Get(id string) *SAMLExchange {
	i.mu.RLock()
	defer i.mu.RUnlock()

	for idx := range i.buffer {
		if i.buffer[idx].ID == id {
			ex := i.buffer[idx]
			return &ex
		}
	}
	return nil
}

func (i *Inspector) Clear() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.buffer = i.buffer[:0]
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
