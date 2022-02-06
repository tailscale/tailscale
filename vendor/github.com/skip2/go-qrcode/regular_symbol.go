// go-qrcode
// Copyright 2014 Tom Harwood

package qrcode

import (
	bitset "github.com/skip2/go-qrcode/bitset"
)

type regularSymbol struct {
	version qrCodeVersion
	mask    int

	data *bitset.Bitset

	symbol *symbol
	size   int
}

// Abbreviated true/false.
const (
	b0 = false
	b1 = true
)

var (
	alignmentPatternCenter = [][]int{
		{}, // Version 0 doesn't exist.
		{}, // Version 1 doesn't use alignment patterns.
		{6, 18},
		{6, 22},
		{6, 26},
		{6, 30},
		{6, 34},
		{6, 22, 38},
		{6, 24, 42},
		{6, 26, 46},
		{6, 28, 50},
		{6, 30, 54},
		{6, 32, 58},
		{6, 34, 62},
		{6, 26, 46, 66},
		{6, 26, 48, 70},
		{6, 26, 50, 74},
		{6, 30, 54, 78},
		{6, 30, 56, 82},
		{6, 30, 58, 86},
		{6, 34, 62, 90},
		{6, 28, 50, 72, 94},
		{6, 26, 50, 74, 98},
		{6, 30, 54, 78, 102},
		{6, 28, 54, 80, 106},
		{6, 32, 58, 84, 110},
		{6, 30, 58, 86, 114},
		{6, 34, 62, 90, 118},
		{6, 26, 50, 74, 98, 122},
		{6, 30, 54, 78, 102, 126},
		{6, 26, 52, 78, 104, 130},
		{6, 30, 56, 82, 108, 134},
		{6, 34, 60, 86, 112, 138},
		{6, 30, 58, 86, 114, 142},
		{6, 34, 62, 90, 118, 146},
		{6, 30, 54, 78, 102, 126, 150},
		{6, 24, 50, 76, 102, 128, 154},
		{6, 28, 54, 80, 106, 132, 158},
		{6, 32, 58, 84, 110, 136, 162},
		{6, 26, 54, 82, 110, 138, 166},
		{6, 30, 58, 86, 114, 142, 170},
	}

	finderPattern = [][]bool{
		{b1, b1, b1, b1, b1, b1, b1},
		{b1, b0, b0, b0, b0, b0, b1},
		{b1, b0, b1, b1, b1, b0, b1},
		{b1, b0, b1, b1, b1, b0, b1},
		{b1, b0, b1, b1, b1, b0, b1},
		{b1, b0, b0, b0, b0, b0, b1},
		{b1, b1, b1, b1, b1, b1, b1},
	}

	finderPatternSize = 7

	finderPatternHorizontalBorder = [][]bool{
		{b0, b0, b0, b0, b0, b0, b0, b0},
	}

	finderPatternVerticalBorder = [][]bool{
		{b0},
		{b0},
		{b0},
		{b0},
		{b0},
		{b0},
		{b0},
		{b0},
	}

	alignmentPattern = [][]bool{
		{b1, b1, b1, b1, b1},
		{b1, b0, b0, b0, b1},
		{b1, b0, b1, b0, b1},
		{b1, b0, b0, b0, b1},
		{b1, b1, b1, b1, b1},
	}
)

func buildRegularSymbol(version qrCodeVersion, mask int,
	data *bitset.Bitset, includeQuietZone bool) (*symbol, error) {

	quietZoneSize := 0
	if includeQuietZone {
		quietZoneSize = version.quietZoneSize()
	}

	m := &regularSymbol{
		version: version,
		mask:    mask,
		data:    data,

		symbol: newSymbol(version.symbolSize(), quietZoneSize),
		size:   version.symbolSize(),
	}

	m.addFinderPatterns()
	m.addAlignmentPatterns()
	m.addTimingPatterns()
	m.addFormatInfo()
	m.addVersionInfo()

	ok, err := m.addData()
	if !ok {
		return nil, err
	}

	return m.symbol, nil
}

func (m *regularSymbol) addFinderPatterns() {
	fpSize := finderPatternSize
	fp := finderPattern
	fpHBorder := finderPatternHorizontalBorder
	fpVBorder := finderPatternVerticalBorder

	// Top left Finder Pattern.
	m.symbol.set2dPattern(0, 0, fp)
	m.symbol.set2dPattern(0, fpSize, fpHBorder)
	m.symbol.set2dPattern(fpSize, 0, fpVBorder)

	// Top right Finder Pattern.
	m.symbol.set2dPattern(m.size-fpSize, 0, fp)
	m.symbol.set2dPattern(m.size-fpSize-1, fpSize, fpHBorder)
	m.symbol.set2dPattern(m.size-fpSize-1, 0, fpVBorder)

	// Bottom left Finder Pattern.
	m.symbol.set2dPattern(0, m.size-fpSize, fp)
	m.symbol.set2dPattern(0, m.size-fpSize-1, fpHBorder)
	m.symbol.set2dPattern(fpSize, m.size-fpSize-1, fpVBorder)
}

func (m *regularSymbol) addAlignmentPatterns() {
	for _, x := range alignmentPatternCenter[m.version.version] {
		for _, y := range alignmentPatternCenter[m.version.version] {
			if !m.symbol.empty(x, y) {
				continue
			}

			m.symbol.set2dPattern(x-2, y-2, alignmentPattern)
		}
	}
}

func (m *regularSymbol) addTimingPatterns() {
	value := true

	for i := finderPatternSize + 1; i < m.size-finderPatternSize; i++ {
		m.symbol.set(i, finderPatternSize-1, value)
		m.symbol.set(finderPatternSize-1, i, value)

		value = !value
	}
}

func (m *regularSymbol) addFormatInfo() {
	fpSize := finderPatternSize
	l := formatInfoLengthBits - 1

	f := m.version.formatInfo(m.mask)

	// Bits 0-7, under the top right finder pattern.
	for i := 0; i <= 7; i++ {
		m.symbol.set(m.size-i-1, fpSize+1, f.At(l-i))
	}

	// Bits 0-5, right of the top left finder pattern.
	for i := 0; i <= 5; i++ {
		m.symbol.set(fpSize+1, i, f.At(l-i))
	}

	// Bits 6-8 on the corner of the top left finder pattern.
	m.symbol.set(fpSize+1, fpSize, f.At(l-6))
	m.symbol.set(fpSize+1, fpSize+1, f.At(l-7))
	m.symbol.set(fpSize, fpSize+1, f.At(l-8))

	// Bits 9-14 on the underside of the top left finder pattern.
	for i := 9; i <= 14; i++ {
		m.symbol.set(14-i, fpSize+1, f.At(l-i))
	}

	// Bits 8-14 on the right side of the bottom left finder pattern.
	for i := 8; i <= 14; i++ {
		m.symbol.set(fpSize+1, m.size-fpSize+i-8, f.At(l-i))
	}

	// Always dark symbol.
	m.symbol.set(fpSize+1, m.size-fpSize-1, true)
}

func (m *regularSymbol) addVersionInfo() {
	fpSize := finderPatternSize

	v := m.version.versionInfo()
	l := versionInfoLengthBits - 1

	if v == nil {
		return
	}

	for i := 0; i < v.Len(); i++ {
		// Above the bottom left finder pattern.
		m.symbol.set(i/3, m.size-fpSize-4+i%3, v.At(l-i))

		// Left of the top right finder pattern.
		m.symbol.set(m.size-fpSize-4+i%3, i/3, v.At(l-i))
	}
}

type direction uint8

const (
	up direction = iota
	down
)

func (m *regularSymbol) addData() (bool, error) {
	xOffset := 1
	dir := up

	x := m.size - 2
	y := m.size - 1

	for i := 0; i < m.data.Len(); i++ {
		var mask bool
		switch m.mask {
		case 0:
			mask = (y+x+xOffset)%2 == 0
		case 1:
			mask = y%2 == 0
		case 2:
			mask = (x+xOffset)%3 == 0
		case 3:
			mask = (y+x+xOffset)%3 == 0
		case 4:
			mask = (y/2+(x+xOffset)/3)%2 == 0
		case 5:
			mask = (y*(x+xOffset))%2+(y*(x+xOffset))%3 == 0
		case 6:
			mask = ((y*(x+xOffset))%2+((y*(x+xOffset))%3))%2 == 0
		case 7:
			mask = ((y+x+xOffset)%2+((y*(x+xOffset))%3))%2 == 0
		}

		// != is equivalent to XOR.
		m.symbol.set(x+xOffset, y, mask != m.data.At(i))

		if i == m.data.Len()-1 {
			break
		}

		// Find next free bit in the symbol.
		for {
			if xOffset == 1 {
				xOffset = 0
			} else {
				xOffset = 1

				if dir == up {
					if y > 0 {
						y--
					} else {
						dir = down
						x -= 2
					}
				} else {
					if y < m.size-1 {
						y++
					} else {
						dir = up
						x -= 2
					}
				}
			}

			// Skip over the vertical timing pattern entirely.
			if x == 5 {
				x--
			}

			if m.symbol.empty(x+xOffset, y) {
				break
			}
		}
	}

	return true, nil
}
