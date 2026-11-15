// Extracted from aweb cli/go/awid strict canonical JSON (MIT; see LICENSE).
package verify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf8"
)

var canonicalIntegerPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// StrictCanonicalJSON encodes a JSON value as the page and task contracts
// define canonical JSON: keys sorted by code point, no insignificant
// whitespace, UTF-8 with only the quotation mark, reverse solidus and C0
// controls escaped (as Python's json.dumps with ensure_ascii=False), and safe
// integers only. It refuses floats, integers beyond 2^53-1, number forms that
// are not plain integers, invalid UTF-8 and non-JSON types. Unlike
// encoding/json it leaves U+2028 and U+2029 unescaped, so its bytes equal the
// Python side's. AWID signing keeps its own serialization (CanonicalJSONValue).
func Canonical(value any) ([]byte, error) {
	var out bytes.Buffer
	if err := writeStrictCanonical(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeStrictCanonical(out *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		return writeStrictString(out, v)
	case json.Number:
		text := string(v)
		if text == "-0" || !canonicalIntegerPattern.MatchString(text) {
			return fmt.Errorf("number %q has no canonical form", text)
		}
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return fmt.Errorf("number %q is outside the safe range", text)
		}
		return writeSafeInteger(out, n)
	case int:
		return writeSafeInteger(out, int64(v))
	case int64:
		return writeSafeInteger(out, v)
	case int32:
		return writeSafeInteger(out, int64(v))
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			if !utf8.ValidString(key) {
				return fmt.Errorf("object key is not valid UTF-8")
			}
			keys = append(keys, key)
		}
		// Byte order of valid UTF-8 is code point order, which is Python's.
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeStrictString(out, key); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := writeStrictCanonical(out, v[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeStrictCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	default:
		return fmt.Errorf("%T has no canonical form", value)
	}
	return nil
}

func writeSafeInteger(out *bytes.Buffer, n int64) error {
	if n > maxSafeInteger || n < -maxSafeInteger {
		return fmt.Errorf("integer %d is outside the safe range", n)
	}
	out.WriteString(strconv.FormatInt(n, 10))
	return nil
}

func writeStrictString(out *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("string is not valid UTF-8")
	}
	out.WriteByte('"')
	writeEscapedString(out, s)
	out.WriteByte('"')
	return nil
}

const maxSafeInteger int64 = 1<<53 - 1

// jsonStringWriter is the part of strings.Builder and bytes.Buffer that
// writeEscapedString uses.
type jsonStringWriter interface {
	io.Writer
	io.StringWriter
	WriteRune(r rune) (int, error)
}

// writeEscapedString writes a JSON-escaped string value (without surrounding quotes).
// It escapes the quotation mark, the reverse solidus and U+0000-U+001F, and
// writes every other code point as UTF-8, as CanonicalJSONValue does.
func writeEscapedString(b jsonStringWriter, s string) {
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
}

// Parse keeps raw number tokens and detects duplicate names before map decoding.
func Parse(raw []byte) (map[string]any, error) {
	if len(raw) > 1<<20 || !utf8.Valid(raw) {
		return nil, fmt.Errorf("invalid text or size")
	}
	if err := checkSurrogates(raw); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := readValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err = dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("object required")
	}
	if _, err = Canonical(obj); err != nil {
		return nil, err
	}
	return obj, nil
}
func readValue(dec *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, fmt.Errorf("too deep")
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch token {
	case json.Delim('{'):
		m := map[string]any{}
		for dec.More() {
			k, e := dec.Token()
			if e != nil {
				return nil, e
			}
			s, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("key required")
			}
			if _, ok = m[s]; ok {
				return nil, fmt.Errorf("duplicate member")
			}
			v, e := readValue(dec, depth+1)
			if e != nil {
				return nil, e
			}
			m[s] = v
		}
		end, e := dec.Token()
		if e != nil || end != json.Delim('}') {
			return nil, fmt.Errorf("object end")
		}
		return m, nil
	case json.Delim('['):
		a := []any{}
		for dec.More() {
			v, e := readValue(dec, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		end, e := dec.Token()
		if e != nil || end != json.Delim(']') {
			return nil, fmt.Errorf("array end")
		}
		return a, nil
	default:
		if _, ok := token.(json.Delim); ok {
			return nil, fmt.Errorf("unexpected delimiter")
		}
		return token, nil
	}
}
func checkSurrogates(raw []byte) error {
	for i := 0; i < len(raw); {
		if raw[i] != '\\' {
			i++
			continue
		}
		if i+1 >= len(raw) {
			return fmt.Errorf("escape truncated")
		}
		if raw[i+1] != 'u' {
			i += 2
			continue
		}
		if i+6 > len(raw) {
			return fmt.Errorf("unicode truncated")
		}
		n, e := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
		if e != nil {
			return e
		}
		i += 6
		if n >= 0xdc00 && n <= 0xdfff {
			return fmt.Errorf("lone surrogate")
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 > len(raw) || raw[i] != '\\' || raw[i+1] != 'u' {
				return fmt.Errorf("lone surrogate")
			}
			low, e := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return fmt.Errorf("lone surrogate")
			}
			i += 6
		}
	}
	return nil
}
