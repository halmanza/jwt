package hash

// MockHasher is a mock implementation of the Hasher interface for testing
type MockHasher struct {
	NameFunc   func() string
	SignFunc   func(data []byte, key []byte) string
	VerifyFunc func(data []byte, signature string, key []byte) bool
}

// Name returns the name of the algorithm
func (m *MockHasher) Name() string {
	if m.NameFunc != nil {
		return m.NameFunc()
	}
	return "HS256"
}

// Sign creates a signature for the given data using the provided key
func (m *MockHasher) Sign(data []byte, key []byte) string {
	if m.SignFunc != nil {
		return m.SignFunc(data, key)
	}
	return "mock-signature"
}

// Verify checks if the signature is valid for the given data and key
func (m *MockHasher) Verify(data []byte, signature string, key []byte) bool {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(data, signature, key)
	}
	return true
}
