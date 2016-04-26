package xxtea

import (
	"bytes"
	"testing"
)

func TestTransform(t *testing.T) {
	b := [...]byte{1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0}
	u := [...]uint32{1, 2, 3, 4, 5}

	if g := uint32ToBytes(u[:]); bytes.Compare(g, b[:]) != 0 {
		t.Errorf("convertion []uint -> []byte failed:: %+v", g)
	}

	if g := bytesToUint32(b[:]); len(g) != len(u) {
		t.Errorf("convertion []byte -> []uint failed:: %+v", g)
	} else {
		for i := range g {
			if g[i] != u[i] {
				t.Errorf("convertion []byte -> []uint failed:: %+v", g)
				break
			}
		}
	}
}
