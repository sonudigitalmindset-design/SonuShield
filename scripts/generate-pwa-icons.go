// Command generate-pwa-icons renders the SonuShield PWA icons
// (dashboard app shell) as PNG files. It uses only the standard
// library. Run from the repository root:
//
//	go run scripts/generate-pwa-icons.go
//
// It writes core/dashboard/icons/icon-*.png. The mark is a plain
// shield silhouette in the dashboard's dark-theme accent on a
// dark field: deliberately simple, official, and readable at
// small sizes. The maskable icon keeps the mark inside the
// central 80% safe zone with full-bleed background.
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

var (
	field  = color.RGBA{R: 0x0d, G: 0x11, B: 0x17, A: 0xff} // dashboard dark background
	accent = color.RGBA{R: 0x4c, G: 0x9a, B: 0xe6, A: 0xff} // dashboard dark accent
	white  = color.RGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
)

// shieldPath reports whether the point (x, y) in a 0..1 square
// lies inside the shield silhouette: a flat top, straight sides
// tapering to a bottom point.
func shieldPath(x, y float64) bool {
	if y < 0.12 || y > 0.90 {
		return false
	}
	// Top edge dips slightly in the middle (classic shield).
	topEdge := 0.12 + 0.05*math.Abs(x-0.5)*2
	if y < topEdge {
		return false
	}
	// Half-width shrinks from 0.38 at the top to 0 at the point.
	t := (y - 0.12) / (0.90 - 0.12)
	half := 0.38 * (1 - t*t*0.85)
	return math.Abs(x-0.5) <= half
}

// checkPath reports whether the point lies inside the check mark
// drawn over the shield, in the same 0..1 square.
func checkPath(x, y float64) bool {
	// Two thick segments: down-right then up-right.
	if !inSegment(x, y, 0.32, 0.52, 0.45, 0.66, 0.055) && !inSegment(x, y, 0.45, 0.66, 0.70, 0.38, 0.055) {
		return false
	}
	return true
}

// inSegment reports whether (x, y) is within width of the segment
// from (x1, y1) to (x2, y2).
func inSegment(x, y, x1, y1, x2, y2, width float64) bool {
	dx, dy := x2-x1, y2-y1
	len2 := dx*dx + dy*dy
	t := ((x-x1)*dx + (y-y1)*dy) / len2
	if t < 0 {
		t = 0
	}
	if t > 1 {
		t = 1
	}
	px, py := x1+t*dx, y1+t*dy
	return math.Hypot(x-px, y-py) <= width
}

func render(size int, maskable bool) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(img, img.Bounds(), &image.Uniform{field}, image.Point{}, draw.Src)
	// Supersample 4x for smooth edges.
	const ss = 4
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			shield, check := 0, 0
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					fx := (float64(px) + (float64(sx)+0.5)/ss) / float64(size)
					fy := (float64(py) + (float64(sy)+0.5)/ss) / float64(size)
					if maskable {
						// Shrink the mark into the central 80%.
						fx = 0.1 + fx*0.8
						fy = 0.1 + fy*0.8
					}
					if shieldPath(fx, fy) {
						shield++
						if checkPath(fx, fy) {
							check++
						}
					}
				}
			}
			total := ss * ss
			if check > 0 {
				// Blend check over shield over field.
				shieldFrac := float64(shield) / float64(total)
				checkFrac := float64(check) / float64(total)
				r := blend(blend(field.R, accent.R, shieldFrac), white.R, checkFrac)
				g := blend(blend(field.G, accent.G, shieldFrac), white.G, checkFrac)
				b := blend(blend(field.B, accent.B, shieldFrac), white.B, checkFrac)
				img.SetRGBA(px, py, color.RGBA{R: r, G: g, B: b, A: 0xff})
			} else if shield > 0 {
				frac := float64(shield) / float64(total)
				img.SetRGBA(px, py, color.RGBA{
					R: blend(field.R, accent.R, frac),
					G: blend(field.G, accent.G, frac),
					B: blend(field.B, accent.B, frac),
					A: 0xff,
				})
			}
		}
	}
	return img
}

func blend(a, b uint8, frac float64) uint8 {
	return uint8(float64(a)*(1-frac) + float64(b)*frac + 0.5)
}

func main() {
	outDir := filepath.Join("core", "dashboard", "icons")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	targets := []struct {
		name     string
		size     int
		maskable bool
	}{
		{"icon-192.png", 192, false},
		{"icon-512.png", 512, false},
		{"icon-180.png", 180, false},
		{"icon-maskable-512.png", 512, true},
	}
	for _, target := range targets {
		path := filepath.Join(outDir, target.name)
		f, err := os.Create(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := png.Encode(f, render(target.size, target.maskable)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		f.Close()
		fmt.Println("wrote " + path)
	}
}
