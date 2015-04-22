package xxtea

func bytesToUint32(data []byte) []uint32 {
	if l := len(data); l%4 != 0 {
		data = append(data, 0, 0, 0, 0)
	}
	rv := make([]uint32, len(data)/4)
	for i := 0; i < len(data)/4; i++ {
		rv[i] = uint32(data[4*i]) +
			uint32(data[4*i+1])<<8 +
			uint32(data[4*i+2])<<16 +
			uint32(data[4*i+3])<<24
	}
	return rv
}

func uint32ToBytes(data []uint32) []byte {
	l := len(data)
	rv := make([]byte, 4*l)
	for i := 0; i < len(data); i++ {
		rv[4*i] = byte(data[i])
		rv[4*i+1] = byte(data[i] >> 8)
		rv[4*i+2] = byte(data[i] >> 16)
		rv[4*i+3] = byte(data[i] >> 24)
	}
	return rv
}
