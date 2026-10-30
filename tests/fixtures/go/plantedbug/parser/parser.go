package parser

// Decode reads a 1-byte length prefix then copies that many bytes into a
// fixed buffer, with an off-by-one OOB read when length == 250.
func Decode(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, nil
	}
	n := int(data[0])
	if n >= len(data) {
		return nil, nil
	}
	buf := make([]byte, n)
	for i := 0; i <= n; i++ { // planted: <= instead of < reads one past buf
		buf[i] = data[1+i]
	}
	return buf, nil
}
