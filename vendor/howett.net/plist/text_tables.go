package plist

type characterSet [4]uint64

func (s *characterSet) Map(ch rune) rune {
	if s.Contains(ch) {
		return ch
	} else {
		return -1
	}
}

func (s *characterSet) Contains(ch rune) bool {
	return ch >= 0 && ch <= 255 && s.ContainsByte(byte(ch))
}

func (s *characterSet) ContainsByte(ch byte) bool {
	return (s[ch/64]&(1<<(ch%64)) > 0)
}

// Bitmap of characters that must be inside a quoted string
// when written to an old-style property list
// Low bits represent lower characters, and each uint64 represents 64 characters.
var gsQuotable = characterSet{
	0x78001385ffffffff,
	0xa800000138000000,
	0xffffffffffffffff,
	0xffffffffffffffff,
}

// 7f instead of 3f in the top line: CFOldStylePlist.c says . is valid, but they quote it.
// ef instead og 6f in the top line: ' will be quoted
var osQuotable = characterSet{
	0xf4007fefffffffff,
	0xf8000001f8000001,
	0xffffffffffffffff,
	0xffffffffffffffff,
}

var whitespace = characterSet{
	0x0000000100003f00,
	0x0000000000000000,
	0x0000000000000000,
	0x0000000000000000,
}

var newlineCharacterSet = characterSet{
	0x0000000000002400,
	0x0000000000000000,
	0x0000000000000000,
	0x0000000000000000,
}

// Bitmap of characters that are valid in base64-encoded strings.
// Used to filter out non-b64 characters to emulate NSDataBase64DecodingIgnoreUnknownCharacters
var base64ValidChars = characterSet{
	0x23ff880000000000,
	0x07fffffe07fffffe,
	0x0000000000000000,
	0x0000000000000000,
}
