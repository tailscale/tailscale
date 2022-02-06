// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package term

/*
Some simple functions to add colors and attributes to terminals.

The base colors are types implementing the Stringer interface, this makes
it very simple to give a color to arbitrary strings. Also handy to have the raw string still
available for comparisons and such.

	g := Green("Green world")
	fmt.Println("Hello",g)
	fmt.Println(Red("Warning!"))

	var col fmt.Stringer
	switch {
	case atk == 0:
		col = Blue("5 FADE OUT")
	case atk < 4:
		col = Green("4 DOUBLE TAKE")
	case atk <10:
		col = Yellow("3 ROUND HOUSE")
	case atk <50:
		col = Red("2 FAST PACE")
	case atk >= 50:
		col = Blinking("1 COCKED PISTOL")
	}
	fmt.Println("Defcon: ",col)
*/

import (
	"errors"
	"fmt"
	"math/rand"
	"strconv"
)

type stringer interface {
	String() string
}

// colorEnable toggles colors on/off.
var colorEnable = true

// ColorEnable activates the terminal colors , this is the default.
func ColorEnable() {
	colorEnable = true
}

// ColorDisable disables the terminal colors.
func ColorDisable() {
	colorEnable = false
}

// Terminal Color and modifier codes
const (
	CSI       = "\033["
	FgBlack   = "30"
	FgRed     = "31"
	FgGreen   = "32"
	FgYellow  = "33"
	FgBlue    = "34"
	FgMagenta = "35"
	FgCyan    = "36"
	FgWhite   = "37"
	FgDefault = "39"
	F256      = "38"
	BgBlack   = "40"
	BgRed     = "41"
	BgGreen   = "42"
	BgYellow  = "43"
	BgBlue    = "44"
	BgMagenta = "45"
	BgCyan    = "46"
	BgWhite   = "47"
	BgDefault = "49"
	Bg256     = "48"
	Blink     = "5"
	Ital      = "3"
	Underln   = "4"
	Faint     = "2"
	Bld       = "1"
	NoMode    = "0"
)

// Standard colors
// Foreground

// Green implements the Stringer interface to print string foreground in Green color.
type Green string

// Blue implements the Stringer interface to print string foreground in Blue color.
type Blue string

// Red implements the Stringer interface to print string foreground in Red color.
type Red string

// Yellow implements the Stringer interface to print string foreground in Yellow color.
type Yellow string

// Magenta implements the Stringer interface to print string foreground in Magenta color.
type Magenta string

// Cyan implements the Stringer interface to print string foreground in Cyan color.
type Cyan string

// White implements the Stringer interface to print string foreground in White color.
type White string

// Black implements the Stringer interface to print string foreground in Black color.
type Black string

// Random implements the Stringer interface to print string foreground in Random color.
type Random string

// Background

// BGreen implements the Stringer interface to print string background in Green color.
type BGreen string

// BBlue implements the Stringer interface to print string background in Blue color.
type BBlue string

// BRed implements the Stringer interface to print string background in Red color.
type BRed string

// BYellow implements the Stringer interface to print string background in Yellow color.
type BYellow string

// BRandom implements the Stringer interface to print string background in Random color.
type BRandom string

// BMagenta implements the Stringer interface to print string background in Magenta color.
type BMagenta string

// BCyan implements the Stringer interface to print string background in Cyan color.
type BCyan string

// BWhite implements the Stringer interface to print string background in White color.
type BWhite string

// BBlack implements the Stringer interface to print string background in Black color.
type BBlack string

// Set color

// Color is the type returned by the colour setters to print any terminal colour.
type Color string

// ColorRandom implements the Stringer interface to print string Random color.
type ColorRandom string

// Color256Random implements the Stringer interface to print string random 256 color Term style.
type Color256Random string

// Some modifiers

// Blinking implements the Stringer interface to print string in Blinking mode.
type Blinking string

// Underline implements the Stringer interface to print string in Underline mode.
type Underline string

// Bold implements the Stringer interface to print string in Bold mode.
type Bold string

//type Bright string -- Doesn't seem to work well

// Italic implements the Stringer interface to print string foreground in Italic color.
type Italic string

// colType takes all the base color types and generates proper modifiers.
func colType(col stringer) string {
	nMode := FgDefault
	var mode, res string
	switch c := col.(type) {
	case Black:
		mode = FgBlack
		res = string(c)
	case Red:
		mode = FgRed
		res = string(c)
	case Green:
		mode = FgGreen
		res = string(c)
	case Yellow:
		mode = FgYellow
		res = string(c)
	case Blue:
		mode = FgBlue
		res = string(c)
	case Magenta:
		mode = FgMagenta
		res = string(c)
	case Cyan:
		mode = FgCyan
		res = string(c)
	case White:
		mode = FgWhite
		res = string(c)
	case BBlack:
		mode = BgBlack
		res = string(c)
	case BRed:
		mode = BgRed
		nMode = BgDefault
		res = string(c)
	case BGreen:
		mode = BgGreen
		nMode = BgDefault
		res = string(c)
	case BYellow:
		mode = BgYellow
		nMode = BgDefault
		res = string(c)
	case BBlue:
		mode = BgBlue
		nMode = BgDefault
		res = string(c)
	case BMagenta:
		mode = BgMagenta
		nMode = BgDefault
		res = string(c)
	case BCyan:
		mode = BgCyan
		nMode = BgDefault
		res = string(c)
	case BWhite:
		mode = BgWhite
		nMode = BgDefault
		res = string(c)
	case Blinking:
		mode = Blink
		nMode = NoMode
		res = string(c)
	case Italic:
		mode = Ital
		nMode = NoMode
		res = string(c)
	case Underline:
		mode = Underln
		nMode = NoMode
		res = string(c)
	case Bold:
		nMode = NoMode
		mode = Bld
		res = string(c)
	default:
		return "unsupported type"
	}
	if !colorEnable {
		return res
	}
	return CSI + mode + "m" + res + CSI + nMode + "m"
}

// Stringers for all the base colors , just fill it in with something and print it
// Foreground

// String implements the Stringer interface for type Green.
func (c Green) String() string {
	return colType(c)
}

// Greenf returns a Green formatted string.
func Greenf(format string, a ...interface{}) string {
	return colType(Green(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type Blue.
func (c Blue) String() string {
	return colType(c)
}

// Bluef returns a Blue formatted string.
func Bluef(format string, a ...interface{}) string {
	return colType(Blue(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type Red.
func (c Red) String() string {
	return colType(c)
}

// Redf returns a Red formatted string.
func Redf(format string, a ...interface{}) string {
	return colType(Red(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type Yellow.
func (c Yellow) String() string {
	return colType(c)
}

// Yellowf returns a Yellow formatted string.
func Yellowf(format string, a ...interface{}) string {
	return colType(Yellow(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type Magenta.
func (c Magenta) String() string {
	return colType(c)
}

// Magentaf returns a Magenta formatted string.
func Magentaf(format string, a ...interface{}) string {
	return colType(Magenta(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type White.
func (c White) String() string {
	return colType(c)
}

// Whitef returns a White formatted string.
func Whitef(format string, a ...interface{}) string {
	return colType(White(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type Black.
func (c Black) String() string {
	return colType(c)
}

// Blackf returns a Black formatted string.
func Blackf(format string, a ...interface{}) string {
	return colType(Black(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type Cyan.
func (c Cyan) String() string {
	return colType(c)
}

// Cyanf returns a Cyan formatted string.
func Cyanf(format string, a ...interface{}) string {
	return colType(Cyan(fmt.Sprintf(format, a...)))
}

// Background

// String implements the Stringer interface for type BGreen.
func (c BGreen) String() string {
	return colType(c)
}

// BGreenf returns a BGreen formatted string.
func BGreenf(format string, a ...interface{}) string {
	return colType(BGreen(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type BBlue.
func (c BBlue) String() string {
	return colType(c)
}

// BBluef returns a BBlue formatted string.
func BBluef(format string, a ...interface{}) string {
	return colType(BBlue(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type BRed.
func (c BRed) String() string {
	return colType(c)
}

// BRedf returns a BRed formatted string.
func BRedf(format string, a ...interface{}) string {
	return colType(BRed(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type BYellow.
func (c BYellow) String() string {
	return colType(c)
}

// BYellowf returns a BYellow formatted string.
func BYellowf(format string, a ...interface{}) string {
	return colType(BYellow(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type BMagenta.
func (c BMagenta) String() string {
	return colType(c)
}

// BMagentaf returns a BMagenta formatted string.
func BMagentaf(format string, a ...interface{}) string {
	return colType(BMagenta(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type BWhite.
func (c BWhite) String() string {
	return colType(c)
}

// BWhitef returns a BWhite formatted string.
func BWhitef(format string, a ...interface{}) string {
	return colType(BWhite(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type BBlack.
func (c BBlack) String() string {
	return colType(c)
}

// BBlackf returns a BBlack formatted string.
func BBlackf(format string, a ...interface{}) string {
	return colType(BBlack(fmt.Sprintf(format, a...)))
}

// String implements the Stringer interface for type BCyan.
func (c BCyan) String() string {
	return colType(c)
}

// BCyanf returns a BCyan formatted string.
func BCyanf(format string, a ...interface{}) string {
	return colType(BCyan(fmt.Sprintf(format, a...)))
}

// Modifier codes

// String implements the Stringer interface for type Blinking.
func (c Blinking) String() string {
	return colType(c)
}

// String implements the Stringer interface for type Underline.
func (c Underline) String() string {
	return colType(c)
}

// String implements the Stringer interface for type Bold.
func (c Bold) String() string {
	return colType(c)
}

// String implements the Stringer interface for type Italic.
func (c Italic) String() string {
	return colType(c)
}

// NewColor gives a type Color back with specified fg/bg colors set that can
// be printed with anything using the Stringer iface.
func NewColor(str string, fg string, bg string) (Color, error) {
	if fg != "" {
		ifg, err := strconv.Atoi(fg)
		if err != nil {
			return Color(""), err
		}
		if ifg < 30 && ifg > 37 {
			return Color(""), errors.New("fg: " + fg + "not a valid color 30-37")
		}
	} else {
		fg = FgDefault
	}
	if bg != "" {
		ibg, err := strconv.Atoi(bg)
		if err != nil {
			return Color(""), err
		}
		if ibg < 40 && ibg > 47 {
			return Color(""), errors.New("fg: " + fg + "not a valid color 40-47")
		}
	} else {
		bg = BgDefault
	}
	return Color(CSI + fg + ";" + bg + "m" + str + CSI + FgDefault + ";" + BgDefault + "m"), nil
}

// String the stringer interface for all base color types.
func (c Color) String() string {
	if !colorEnable {
		clean := make([]byte, 0, len(c))
		src := []byte(c)
	L1:
		for i := 0; i < len(src); i++ {
			// Shortest possible mod.
			if len(src) < i+4 {
				clean = append(clean, src[i:]...)
				return string(clean)
			}
			if string(src[i:i+2]) == CSI {
				// Save current index incase this is not a term mod code.
				s := i
				// skip forward to end of mod
				for i += 2; i < len(src); i++ {
					switch src[i] {
					case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ';':
						// Legal characters in a term mod code.
						continue
					case 'm':
						// End of the term mod code.
						continue L1
					default:
						// Not a term mod code.
						i = s
						break
					}
				}
			}
			clean = append(clean, src[i])
		}
		return string(clean)
	}
	return string(c)
}

// NewColor256 gives a type Color back using Term 256 color that can be printed with anything using the Stringer iface.
func NewColor256(str string, fg string, bg string) (Color, error) {
	if fg != "" {
		ifg, err := strconv.Atoi(fg)
		if err != nil {
			return Color(""), err
		}
		if ifg < 0 && ifg > 256 {
			return Color(""), errors.New("fg: " + fg + " not a valid color 0-256")
		}
	}
	if bg != "" {
		ibg, err := strconv.Atoi(bg)
		if err != nil {
			return Color(""), err
		}
		if ibg < 0 && ibg > 256 {
			return Color(""), errors.New("bg: " + bg + " not a valid color 0-256")
		}
	}
	tstr := CSI + F256 + ";5;" + fg + ";" + Bg256 + ";5;" + bg + "m"
	tstr += str
	return Color(tstr + CSI + FgDefault + ";5;" + BgDefault + ";5;" + "m"), nil
}

// NewColorRGB takes R G B and returns a ColorRGB type that can be printed by anything using the Stringer iface.
// Only Konsole to my knowledge that supports 24bit color
func NewColorRGB(str string, red uint8, green uint8, blue uint8) Color {
	ired := strconv.Itoa(int(red))
	igreen := strconv.Itoa(int(green))
	iblue := strconv.Itoa(int(blue))
	tstr := CSI + F256 + ";2;" + ired + ";" + igreen + ";" + iblue + "m"
	tstr += str
	return Color(tstr + CSI + FgDefault + ";5;" + BgDefault + ";5;" + "m")
}

// String is a random color stringer.
func (c ColorRandom) String() string {
	if !colorEnable {
		return string(c)
	}
	ifg := rand.Int()%8 + 30
	ibg := rand.Int()%8 + 40
	res := CSI + strconv.Itoa(ifg) + ";" + strconv.Itoa(ibg) + "m"
	res += string(c)
	res += CSI + strconv.Itoa(ifg) + ";" + strconv.Itoa(ibg) + "m"
	return res
}

// String gives a random fg color everytime it's printed.
func (c Random) String() string {
	if !colorEnable {
		return string(c)
	}
	ifg := int(rand.Int()%8 + 30)
	res := CSI + strconv.Itoa(ifg) + "m"
	res += string(c) + strconv.Itoa(int(ifg))
	res += CSI + FgDefault + "m"
	return res
}

// String gives a random bg color everytime it's printed.
func (c BRandom) String() string {
	if !colorEnable {
		return string(c)
	}
	ibg := rand.Int()%8 + 40
	res := CSI + strconv.Itoa(ibg) + "m"
	res += string(c) + strconv.Itoa(ibg)
	res += CSI + BgDefault + "m"
	return res
}

// NewCombo Takes a combination of modes and return a string with them all combined.
func NewCombo(s string, mods ...string) Color {
	var col, bcol, mod bool
	modstr := CSI
	tracking := make(map[string]bool)
	for _, m := range mods {
		switch m {
		case FgBlack, FgRed, FgGreen, FgYellow, FgBlue, FgMagenta, FgCyan, FgWhite:
			if col {
				continue
			}
			col = true
		case BgBlack, BgRed, BgGreen, BgYellow, BgBlue, BgMagenta, BgCyan, BgWhite:
			if bcol {
				continue
			}
			bcol = true
		case Bld, Faint, Ital, Underln, Blink:
			if tracking[m] {
				continue
			}
			tracking[m] = true
			mod = true
		default:
			continue
		}
		modstr += m + ";"
	}
	end := CSI
	if col {
		end += FgDefault
	}
	if bcol {
		if col {
			end += ";"
		}
		end += BgDefault
	}
	if mod {
		if col || bcol {
			end += ";"
		}
		end += NoMode
	}
	end += "m"
	modstr = modstr[:len(modstr)-1] + "m"
	modstr += s
	modstr += end
	return Color(modstr)
}

// TestTerm tries out most of the functions in this package and return
// a colourful string. Could be used to check what your terminal supports.
func TestTerm() string {
	res := "Standard 8:\n"
	res += "Fg:\t"
	for c := 30; c < 38; c++ {
		tres, _ := NewColor("#", strconv.Itoa(c), "")
		res += tres.String()
	}
	res += "\nBg:\t"
	for c := 40; c < 48; c++ {
		tres, _ := NewColor(" ", "", strconv.Itoa(c))
		res += tres.String()
	}
	res += "\nStandard 16:\t"
	for c := 0; c < 16; c++ {
		tcol, _ := NewColor256(" ", "", strconv.Itoa(c))
		res += tcol.String()
	}
	res += "\n"
	res += "256 Col:\n"
	// 6x6x6 cubes are trendy
	for row, base := 1, 0; row <= 6; row++ {
		base = (row * 6) + 9 // Step over the first 16 base colors
		for cubes := 1; cubes <= 6; cubes++ {
			for column := 1; column <= 6; column++ {
				tcol, _ := NewColor256(" ", "", strconv.Itoa(base+column))
				res += tcol.String()
			}
			base += 36 // 6 * 6
		}
		res += "\n"
	}
	// Grayscale left.
	res += "Grayscales:\n"
	for c := 232; c <= 255; c++ {
		tcol, _ := NewColor256(" ", "", strconv.Itoa(c))
		res += tcol.String()
	}
	return res
}
