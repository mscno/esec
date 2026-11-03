package commands

import (
	"encoding/json"
	"errors"
	"io"
	"sync"

	"filippo.io/age/plugin"
)

// guiProtocol runs for one read, over anonymous child-process pipes only.
// No sockets, persistent PIN cache, shell arguments, or disk files carry replies.
type guiProtocol struct {
	out  *json.Encoder
	in   *json.Decoder
	mu   sync.Mutex
	next int
}
type guiPrompt struct {
	Type    string `json:"type"`
	ID      int    `json:"id,omitempty"`
	Plugin  string `json:"plugin,omitempty"`
	Message string `json:"message"`
	Secret  bool   `json:"secret,omitempty"`
	Yes     string `json:"yes,omitempty"`
	No      string `json:"no,omitempty"`
}
type guiReply struct {
	ID        int    `json:"id"`
	Value     string `json:"value"`
	Confirmed bool   `json:"confirmed"`
	Cancelled bool   `json:"cancelled"`
}

func newGUIProtocol(in io.Reader, out io.Writer) *guiProtocol {
	return &guiProtocol{out: json.NewEncoder(out), in: json.NewDecoder(io.LimitReader(in, 64<<10))}
}
func (g *guiProtocol) request(p guiPrompt) (guiReply, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.next++
	p.ID = g.next
	if err := g.out.Encode(p); err != nil {
		return guiReply{}, errors.New("could not request hardware approval")
	}
	var r guiReply
	if err := g.in.Decode(&r); err != nil || r.ID != p.ID || r.Cancelled {
		return guiReply{}, errors.New("hardware approval cancelled")
	}
	return r, nil
}
func (g *guiProtocol) ui() *plugin.ClientUI {
	return &plugin.ClientUI{
		DisplayMessage: func(name, message string) error {
			g.mu.Lock()
			defer g.mu.Unlock()
			return g.out.Encode(guiPrompt{Type: "message", Plugin: name, Message: message})
		},
		RequestValue: func(name, prompt string, secret bool) (string, error) {
			r, e := g.request(guiPrompt{Type: "input", Plugin: name, Message: prompt, Secret: secret})
			return r.Value, e
		},
		Confirm: func(name, prompt, yes, no string) (bool, error) {
			r, e := g.request(guiPrompt{Type: "confirm", Plugin: name, Message: prompt, Yes: yes, No: no})
			return r.Confirmed, e
		},
	}
}
