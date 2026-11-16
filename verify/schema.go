package verify

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var wireSchema = func() map[string]any {
	var schema map[string]any
	if e := json.Unmarshal([]byte(schemaJSON), &schema); e != nil {
		panic(e)
	}
	return schema
}()

func domain(name string) []byte {
	return []byte(wireSchema["x-domains"].(map[string]any)[name].(string))
}
func validate(kind string, v any) error {
	return validateNode(wireSchema["$defs"].(map[string]any)[kind].(map[string]any), v)
}
func validateNode(s map[string]any, v any) error {
	return validateNodeScoped(s, v, wireSchema["$defs"].(map[string]any))
}
func validateNodeScoped(s map[string]any, v any, definitions map[string]any) error {
	if local, ok := s["$defs"].(map[string]any); ok {
		definitions = local
	}
	bad := func() error { return fmt.Errorf("invalid_shape") }
	if ref, ok := s["$ref"].(string); ok {
		child, ok := definitions[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
		if !ok {
			return bad()
		}
		return validateNodeScoped(child, v, definitions)
	}
	if options, ok := s["oneOf"].([]any); ok {
		n := 0
		for _, o := range options {
			if validateNodeScoped(o.(map[string]any), v, definitions) == nil {
				n++
			}
		}
		if n != 1 {
			return bad()
		}
		return nil
	}
	if typ, ok := s["type"].(string); ok {
		switch typ {
		case "object":
			if _, ok := v.(map[string]any); !ok {
				return bad()
			}
		case "array":
			if _, ok := v.([]any); !ok {
				return bad()
			}
		case "string":
			if _, ok := v.(string); !ok {
				return bad()
			}
		case "boolean":
			if _, ok := v.(bool); !ok {
				return bad()
			}
		case "integer":
			if _, ok := v.(json.Number); !ok {
				return bad()
			}
		case "null":
			if v != nil {
				return bad()
			}
		default:
			return bad()
		}
	}
	if want, ok := s["const"]; ok {
		if n, ok := v.(json.Number); ok {
			f, e := n.Float64()
			if e != nil || f != want {
				return bad()
			}
		} else if v != want {
			return bad()
		}
	}
	if options, ok := s["enum"].([]any); ok {
		found := false
		for _, o := range options {
			if n, ok := v.(json.Number); ok {
				f, e := n.Float64()
				found = found || (e == nil && f == o)
			} else {
				found = found || v == o
			}
		}
		if !found {
			return bad()
		}
	}
	switch x := v.(type) {
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		required, _ := s["required"].([]any)
		for _, r := range required {
			if _, ok := x[r.(string)]; !ok {
				return bad()
			}
		}
		closed, _ := s["additionalProperties"].(bool)
		for k, value := range x {
			p, ok := props[k]
			if !ok {
				if closed == false && s["additionalProperties"] != nil {
					return bad()
				}
				continue
			}
			if e := validateNodeScoped(p.(map[string]any), value, definitions); e != nil {
				return e
			}
		}
	case []any:
		if unique, _ := s["uniqueItems"].(bool); unique {
			seen := make(map[string]bool, len(x))
			for _, item := range x {
				raw, err := Canonical(item)
				if err != nil || seen[string(raw)] {
					return bad()
				}
				seen[string(raw)] = true
			}
		}
		if n, ok := s["minItems"].(float64); ok && len(x) < int(n) {
			return bad()
		}
		if n, ok := s["maxItems"].(float64); ok && len(x) > int(n) {
			return bad()
		}
		if item, ok := s["items"].(map[string]any); ok {
			for _, v := range x {
				if e := validateNodeScoped(item, v, definitions); e != nil {
					return e
				}
			}
		}
	case string:
		if n, ok := s["minLength"].(float64); ok && len([]rune(x)) < int(n) {
			return bad()
		}
		if n, ok := s["maxLength"].(float64); ok && len([]rune(x)) > int(n) {
			return bad()
		}
		if p, ok := s["pattern"].(string); ok {
			matched, e := regexp.MatchString(p, x)
			if e != nil || !matched {
				return bad()
			}
		}
	case json.Number:
		n, e := x.Int64()
		if e != nil {
			return bad()
		}
		if min, ok := s["minimum"].(float64); ok && n < int64(min) {
			return bad()
		}
		if max, ok := s["maximum"].(float64); ok && n > int64(max) {
			return bad()
		}
	}
	return nil
}

// One exact site check for receipts, enrollment and service bindings.
func checkSite(origin, rp string) error {
	props := wireSchema["$defs"].(map[string]any)["binding_body"].(map[string]any)["properties"].(map[string]any)
	if validateNode(props["rp_id"].(map[string]any), rp) != nil || validateNode(props["origin"].(map[string]any), origin) != nil {
		return refuse("origin_invalid")
	}
	u, e := url.Parse(origin)
	if e != nil {
		return refuse("origin_invalid")
	}
	port := u.Port()
	suffix := ""
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return refuse("origin_invalid")
		}
		suffix = ":" + port
	}
	if u.Scheme != "https" || u.Hostname() != rp || origin != "https://"+rp+suffix || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return refuse("origin_invalid")
	}
	return nil
}
