package verify

// RefusalCode is a machine-readable reason from a pure verifier. It carries
// no HTTP status or application permission; Error() retains the published text.
type RefusalCode string

const (
	EnrollmentEvidenceUnsupported RefusalCode = "enrollment_evidence_unsupported"
	EnrollmentEvidenceInvalid     RefusalCode = "enrollment_evidence_invalid"
)

// RefusalError lets consumers distinguish unsupported evidence from invalid
// evidence without interpreting human-readable error text.
type RefusalError struct {
	Code RefusalCode
}

func (e *RefusalError) Error() string { return string(e.Code) }

func refuse(code RefusalCode) error { return &RefusalError{Code: code} }
