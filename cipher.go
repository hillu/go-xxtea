// This package implements XXTEA encryption as defined in Needham and Wheeler's
// 1998 technical report, "Correction to XTEA."
package xxtea

// For details, see http://www.movable-type.co.uk/scripts/xxtea.pdf

import "strconv"

// The XXTEA block size in bytes.
const BlockSize = 8

// A Cipher is an instance of an XXTEA cipher using a particular key.
type Cipher struct {
	k [4]uint32
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/xtea: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new Cipher. The key argument should
// be the XXTEA key. XXTEA only supports 128 bit (16 byte) keys which
// are converted internally into 4 little-endian uint32 values.
func NewCipher(key []byte) (*Cipher, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 16:
		break
	}
	u := bytesToUint32(key)
	c := new(Cipher)
	copy(c.k[:], u)
	return c, nil
}

func (c *Cipher) BlockSize() int { return BlockSize }

func (c *Cipher) Encrypt(dst, src []byte) {
	v := bytesToUint32(src)
	c.BlockEncrypt(v)
	copy(dst, uint32ToBytes(v))
}

func (c *Cipher) Decrypt(dst, src []byte) {
	v := bytesToUint32(src)
	c.BlockDecrypt(v)
	copy(dst, uint32ToBytes(v))
}

const Delta = 0x9e3779b9

// BlockEncrypt encrypts the []uint32 represtentation of a block,
// in-place.
func (c *Cipher) BlockEncrypt(v []uint32) {
	n := len(v)
	y := v[0]
	z := v[n-1]
	q := 6 + 52/n

	var sum uint32
	for q > 0 {
		q--
		sum += Delta
		e := (sum >> 2) & 3
		var p int
		for p = 0; p < n-1; p++ {
			y = v[p+1]
			v[p] += ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (c.k[uint32(p)&3^e] ^ z))
			z = v[p]
		}
		y = v[0]
		v[n-1] += ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (c.k[uint32(p)&3^e] ^ z))
		z = v[n-1]
	}
}

// BlockDecrypt decrypts the []uint32 represtentation of a block,
// in-place.
func (c *Cipher) BlockDecrypt(v []uint32) {
	n := len(v)
	y := v[0]
	z := v[n-1]
	q := 6 + 52/n

	sum := uint32(q * Delta)
	for sum != 0 {
		e := (sum >> 2) & 3
		var p int
		for p = n - 1; p > 0; p-- {
			z = v[p-1]
			v[p] -= ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (c.k[uint32(p)&3^e] ^ z))
			y = v[p]
		}
		z = v[n-1]
		v[0] -= ((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (c.k[uint32(p)&3^e] ^ z))
		y = v[0]
		sum -= Delta
	}
}
