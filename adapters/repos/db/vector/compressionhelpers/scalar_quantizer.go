//                           _       _
// __      _____  __ ___   ___  __ _| |_ ___
// \ \ /\ / / _ \/ _` \ \ / / |/ _` | __/ _ \
//  \ V  V /  __/ (_| |\ V /| | (_| | ||  __/
//   \_/\_/ \___|\__,_| \_/ |_|\__,_|\__\___|
//
//  Copyright © 2016 - 2024 Weaviate B.V. All rights reserved.
//
//  CONTACT: hello@weaviate.io
//

package compressionhelpers

import (
	"encoding/binary"
	"math"

	"github.com/pkg/errors"
	"github.com/weaviate/weaviate/adapters/repos/db/vector/hnsw/distancer"
)

const (
	codes     = 64.0
	codes2    = codes * codes
	codesLasq = 16.0
)

var l2SquaredByteImpl func(a, b []byte) uint32 = func(a, b []byte) uint32 {
	var sum uint32

	for i := range a {
		diff := uint32(a[i]) - uint32(b[i])
		sum += diff * diff
	}

	return sum
}

var dotByteImpl func(a, b []byte) uint32 = func(a, b []byte) uint32 {
	var sum uint32

	for i := range a {
		sum += uint32(a[i]) * uint32(b[i])
	}

	return sum
}

type ScalarQuantizer struct {
	a         float32
	b         float32
	a2        float32
	ab        float32
	ib2       float32
	distancer distancer.Provider
}

func (sq *ScalarQuantizer) DistanceBetweenCompressedVectors(x, y []byte) (float32, error) {
	if len(x) != len(y) {
		return 0, errors.Errorf("vector lengths don't match: %d vs %d",
			len(x), len(y))
	}
	switch sq.distancer.Type() {
	case "l2-squared":
		return sq.a2 * float32(l2SquaredByteImpl(x[:len(x)-2], y[:len(y)-2])), nil
	case "dot":
		return -(sq.a2*float32(dotByteImpl(x[:len(x)-2], y[:len(y)-2])) + sq.ab*float32(sq.norm(x)+sq.norm(y)) + sq.ib2), nil
	case "cosine-dot":
		return 1 - (sq.a2*float32(dotByteImpl(x[:len(x)-2], y[:len(y)-2])) + sq.ab*float32(sq.norm(x)+sq.norm(y)) + sq.ib2), nil
	}
	return 0, errors.Errorf("Distance not supported yet %s", sq.distancer)
}

func (sq *ScalarQuantizer) DistanceBetweenCompressedAndUncompressedVectors(x []float32, encoded []byte) (float32, error) {
	return sq.DistanceBetweenCompressedVectors(sq.Encode(x), encoded)
}

func NewScalarQuantizer(data [][]float32, distance distancer.Provider) *ScalarQuantizer {
	if len(data) == 0 {
		return nil
	}

	sq := &ScalarQuantizer{
		distancer: distance,
	}
	sq.b = data[0][0]
	for i := 1; i < len(data); i++ {
		vec := data[i]
		for _, x := range vec {
			if x < sq.b {
				sq.a += sq.b - x
				sq.b = x
			} else if x-sq.b > sq.a {
				sq.a = x - sq.b
			}
		}
	}
	sq.a2 = sq.a * sq.a / codes2
	sq.ab = sq.a * sq.b / codes
	sq.ib2 = sq.b * sq.b * float32(len(data[0]))
	return sq
}

func codeFor(x, a, b, codes float32) byte {
	if x < b {
		return 0
	} else if x-b > a {
		return byte(codes)
	} else {
		return byte((x - b) * codes / a)
	}
}

func (sq *ScalarQuantizer) Encode(vec []float32) []byte {
	var sum uint16 = 0
	code := make([]byte, len(vec)+2)
	for i := 0; i < len(vec); i++ {
		code[i] = codeFor(vec[i], sq.a, sq.b, codes)
		sum += uint16(code[i])
	}
	binary.BigEndian.PutUint16(code[len(vec):], sum)
	return code
}

func (sq *ScalarQuantizer) norm(code []byte) uint16 {
	return binary.BigEndian.Uint16(code[len(code)-2:])
}

type SQDistancer struct {
	x          []float32
	sq         *ScalarQuantizer
	compressed []byte
}

func (sq *ScalarQuantizer) NewDistancer(a []float32) *SQDistancer {
	return &SQDistancer{
		x:          a,
		sq:         sq,
		compressed: sq.Encode(a),
	}
}

func (d *SQDistancer) Distance(x []byte) (float32, bool, error) {
	dist, err := d.sq.DistanceBetweenCompressedVectors(d.compressed, x)
	return dist, err == nil, err
}

func (d *SQDistancer) DistanceToFloat(x []float32) (float32, bool, error) {
	if len(d.x) > 0 {
		return d.sq.distancer.SingleDist(d.x, x)
	}
	xComp := d.sq.Encode(x)
	dist, err := d.sq.DistanceBetweenCompressedVectors(d.compressed, xComp)
	return dist, err == nil, err
}

func (sq *ScalarQuantizer) NewQuantizerDistancer(a []float32) quantizerDistancer[byte] {
	return sq.NewDistancer(a)
}

func (sq *ScalarQuantizer) NewCompressedQuantizerDistancer(a []byte) quantizerDistancer[byte] {
	return &SQDistancer{
		x:          nil,
		sq:         sq,
		compressed: a,
	}
}

func (sq *ScalarQuantizer) ReturnQuantizerDistancer(distancer quantizerDistancer[byte]) {}

func (sq *ScalarQuantizer) CompressedBytes(compressed []byte) []byte {
	return compressed
}

func (sq *ScalarQuantizer) FromCompressedBytes(compressed []byte) []byte {
	return compressed
}

func (sq *ScalarQuantizer) ExposeFields() PQData {
	return PQData{}
}

type LaScalarQuantizer struct {
	distancer distancer.Provider
	dims      int
	means     []float32
}

func NewLocallyAdaptiveScalarQuantizer(data [][]float32, distance distancer.Provider) *LaScalarQuantizer {
	dims := len(data[0])
	means := make([]float32, dims)
	for _, v := range data {
		for i := range v {
			means[i] += v[i]
		}
	}
	for i := range data[0] {
		means[i] /= float32(dims)
	}
	return &LaScalarQuantizer{
		distancer: distance,
		dims:      dims,
		means:     means,
	}
}

func (lasq *LaScalarQuantizer) Encode(vec []float32) []byte {
	var sum uint16 = 0
	min, max := float32(math.MaxFloat32), float32(-math.MaxFloat32)
	for i, x := range vec {
		corrected := x - lasq.means[i]
		if min > corrected {
			min = corrected
		}
		if max < corrected {
			max = corrected
		}
	}
	code := make([]byte, len(vec)+10)

	for i := 0; i < len(vec); i++ {
		for i := 0; i < len(vec); i++ {
			code[i] = codeFor(vec[i]-lasq.means[i], max-min, min, codesLasq)
			sum += uint16(code[i])
		}
		binary.BigEndian.PutUint16(code[len(vec):], sum)
		binary.BigEndian.PutUint32(code[len(vec)+2:], math.Float32bits(min))
		binary.BigEndian.PutUint32(code[len(vec)+6:], math.Float32bits(max))
	}
	binary.BigEndian.PutUint16(code[len(vec):], sum)
	return code
}

func (lasq *LaScalarQuantizer) DistanceBetweenCompressedVectors(x, y []byte) (float32, error) {
	if len(x) != len(y) {
		return 0, errors.Errorf("vector lengths don't match: %d vs %d",
			len(x), len(y))
	}

	bx := lasq.lowerBound(x)
	ax := (lasq.upperBound(x) - bx) / codesLasq
	by := lasq.lowerBound(y)
	ay := (lasq.upperBound(y) - by) / codesLasq
	correctedX := make([]float32, lasq.dims)
	correctedY := make([]float32, lasq.dims)
	for i := 0; i < lasq.dims; i++ {
		correctedX[i] = float32(x[i])*ax + bx + lasq.means[i]
		correctedY[i] = float32(y[i])*ay + by + lasq.means[i]
	}
	d, _, err := lasq.distancer.SingleDist(correctedX, correctedY)
	return d, err
}

func (lasq *LaScalarQuantizer) lowerBound(code []byte) float32 {
	return math.Float32frombits(binary.BigEndian.Uint32(code[len(code)-8:]))
}

func (lasq *LaScalarQuantizer) upperBound(code []byte) float32 {
	return math.Float32frombits(binary.BigEndian.Uint32(code[len(code)-4:]))
}

type LASQDistancer struct {
	x          []float32
	sq         *LaScalarQuantizer
	compressed []byte
}

func (sq *LaScalarQuantizer) NewDistancer(a []float32) *LASQDistancer {
	return &LASQDistancer{
		x:          a,
		sq:         sq,
		compressed: sq.Encode(a),
	}
}

func (d *LASQDistancer) Distance(x []byte) (float32, bool, error) {
	dist, err := d.sq.DistanceBetweenCompressedVectors(d.compressed, x)
	return dist, err == nil, err
}

func (d *LASQDistancer) DistanceToFloat(x []float32) (float32, bool, error) {
	if len(d.x) > 0 {
		return d.sq.distancer.SingleDist(d.x, x)
	}
	xComp := d.sq.Encode(x)
	dist, err := d.sq.DistanceBetweenCompressedVectors(d.compressed, xComp)
	return dist, err == nil, err
}

func (sq *LaScalarQuantizer) NewQuantizerDistancer(a []float32) quantizerDistancer[byte] {
	return sq.NewDistancer(a)
}

func (sq *LaScalarQuantizer) NewCompressedQuantizerDistancer(a []byte) quantizerDistancer[byte] {
	return &LASQDistancer{
		x:          nil,
		sq:         sq,
		compressed: a,
	}
}

func (sq *LaScalarQuantizer) ReturnQuantizerDistancer(distancer quantizerDistancer[byte]) {}

func (sq *LaScalarQuantizer) CompressedBytes(compressed []byte) []byte {
	return compressed
}

func (sq *LaScalarQuantizer) FromCompressedBytes(compressed []byte) []byte {
	return compressed
}

func (sq *LaScalarQuantizer) ExposeFields() PQData {
	return PQData{}
}

func (sq *LaScalarQuantizer) DistanceBetweenCompressedAndUncompressedVectors(x []float32, encoded []byte) (float32, error) {
	return sq.DistanceBetweenCompressedVectors(sq.Encode(x), encoded)
}