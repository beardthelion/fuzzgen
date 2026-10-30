package codec

import "io"

func Decode(data []byte) (string, error) { return string(data), nil }

func DecodeStr(s string) (string, error) { return s, nil }

func DecodeReader(r io.Reader) error { return nil }

func DecodeParts(data []byte, label string) error { return nil }

func Nothing() {}

type Header struct{}

func (h *Header) UnmarshalSSZ(data []byte) error { return nil }
func (h *Header) DecodeRLP(s any) error          { return nil }
