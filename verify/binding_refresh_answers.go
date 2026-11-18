package verify

// BindingRefreshServiceError retains controlled issuer/service advice.
type BindingRefreshServiceError struct {
	Service *ServiceError
	Advice  string
}

func (e *BindingRefreshServiceError) Error() string { return e.Service.Error() }
func (e *BindingRefreshServiceError) Unwrap() error { return e.Service }

// BindingRefreshAnswerInput binds a result to the exact submitted signed B.
type BindingRefreshAnswerInput struct {
	Status  int
	Binding map[string]any
}

// ReadBindingRefreshAnswer implements binding-refresh-v1.json without changing
// historical evidence or inferring current authority from an answer.
func ReadBindingRefreshAnswer(body map[string]any, in BindingRefreshAnswerInput) (map[string]any, error) {
	if in.Status >= 400 {
		if validate("binding_refresh_error", body) != nil {
			return nil, refuse("service_response_invalid")
		}
		details, ok := body["error"].(map[string]any)
		if !ok {
			return nil, refuse("service_response_invalid")
		}
		code, ok := details["code"].(string)
		if !ok {
			return nil, refuse("service_response_invalid")
		}
		advice := ""
		if raw, exists := details["message"]; exists {
			var valid bool
			advice, valid = raw.(string)
			if !valid {
				return nil, refuse("service_response_invalid")
			}
		}
		return nil, &BindingRefreshServiceError{Service: &ServiceError{Code: code, HTTPStatus: in.Status}, Advice: advice}
	}
	if in.Status != 200 || validate("binding_refresh_answer", body) != nil || validate("binding", in.Binding) != nil {
		return nil, refuse("service_response_invalid")
	}
	b, ok := in.Binding["binding"].(map[string]any)
	if !ok {
		return nil, refuse("service_response_invalid")
	}
	if body["person"] != b["person"] {
		return nil, refuse("person_mismatch")
	}
	digest, err := Commitment("binding_commitment", in.Binding)
	if err != nil {
		return nil, refuse("service_response_invalid")
	}
	if body["binding_commitment"] != digest {
		return nil, refuse("binding_mismatch")
	}
	return body, nil
}
