package encoding

import "encoding/json"

// StructToJsonBytes converts a struct to JSON bytes
func StructToJsonBytes(v any) ([]byte, error) {
	return json.Marshal(v)
}

// JsonBytesToStruct converts JSON bytes to a struct
func JsonBytesToStruct(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
