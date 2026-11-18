package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestBindingRefreshAnswerVectors(t *testing.T) {
	raw, err := os.ReadFile("../vectors/binding-refresh-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			ID      string         `json:"id"`
			Binding map[string]any `json:"binding"`
			Answer  map[string]any `json:"answer"`
			Status  int            `json:"status"`
			Accept  bool           `json:"accept"`
			Code    string         `json:"code"`
		} `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Cases {
		t.Run(c.ID, func(t *testing.T) {
			_, err := ReadBindingRefreshAnswer(c.Answer, BindingRefreshAnswerInput{Status: c.Status, Binding: c.Binding})
			if (err == nil) != c.Accept {
				t.Fatalf("accepted=%v want %v: %v", err == nil, c.Accept, err)
			}
			if err != nil && err.Error() != c.Code {
				t.Fatalf("code=%v want %s", err, c.Code)
			}
			if c.Status >= 400 {
				var refusal *BindingRefreshServiceError
				if !errors.As(err, &refusal) || refusal.Advice == "" {
					t.Fatal("missing refusal advice")
				}
			}
		})
	}
}
