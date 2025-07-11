//                           _       _
// __      _____  __ ___   ___  __ _| |_ ___
// \ \ /\ / / _ \/ _` \ \ / / |/ _` | __/ _ \
//  \ V  V /  __/ (_| |\ V /| | (_| | ||  __/
//   \_/\_/ \___|\__,_| \_/ |_|\__,_|\__\___|
//
//  Copyright © 2016 - 2025 Weaviate B.V. All rights reserved.
//
//  CONTACT: hello@weaviate.io
//

package lsmkv

import (
	"crypto/rand"
	"fmt"
	randInsecure "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func BenchmarkBytes(b *testing.B) {
	for _, val := range []int{10, 100, 1000, 10000, 24 * 1024} {
		b.Run(fmt.Sprintf("%d", val), func(b *testing.B) {
			kv := MapPair{
				Key:   []byte("my-key-1"),
				Value: make([]byte, val),
			}
			for i := 0; i < len(kv.Value); i++ {
				kv.Value[i] = byte(randInsecure.Intn(100))
			}
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := kv.Bytes()
				require.NoError(b, err)
			}
		})
	}
}

func BenchmarkMapDecoderDoPartial_SingleKey(b *testing.B) {
	before := []MapPair{{
		Key:   []byte("my-key-1"),
		Value: []byte("my-value-1"),
	}}

	encoded, err := newMapEncoder().DoMulti(before)
	require.Nil(b, err)

	md := newMapDecoder()

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		md.DoPartial(encoded)
	}
}

func BenchmarkMapPairFromBytes(b *testing.B) {
	before := MapPair{
		Key:   []byte("my-key-1"),
		Value: make([]byte, 24*1024),
	}

	rand.Read(before.Value)

	encoded, err := before.Bytes()
	require.Nil(b, err)

	b.ReportAllocs()

	target := MapPair{}

	for i := 0; i < b.N; i++ {
		target.FromBytes(encoded, false)
	}
}

func BenchmarkMapPairFromBytesReusable_Fits(b *testing.B) {
	before := MapPair{
		Key:   []byte("my-key-1"),
		Value: make([]byte, 24*1024),
	}

	rand.Read(before.Value)

	encoded, err := before.Bytes()
	require.Nil(b, err)

	target := MapPair{
		Key:   make([]byte, 8),
		Value: make([]byte, 24*1024),
	}

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := target.FromBytesReusable(encoded, false)
		require.Nil(b, err)
	}

	assert.Equal(b, before.Key, target.Key)
	assert.Equal(b, before.Value, target.Value)
}

func BenchmarkMapPairFromBytesReusable_BuffersTooLarge(b *testing.B) {
	before := MapPair{
		Key:   []byte("my-key-1"),
		Value: make([]byte, 24*1024),
	}

	rand.Read(before.Value)

	encoded, err := before.Bytes()
	require.Nil(b, err)

	target := MapPair{
		Key:   make([]byte, 100),
		Value: make([]byte, 100*1024),
	}

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := target.FromBytesReusable(encoded, false)
		require.Nil(b, err)
	}

	assert.Equal(b, before.Key, target.Key)
	assert.Equal(b, before.Value, target.Value)
}

func BenchmarkMapPairFromBytesReusable_BuffersTooSmall(b *testing.B) {
	before := MapPair{
		Key:   []byte("my-key-1"),
		Value: make([]byte, 24*1024),
	}

	rand.Read(before.Value)

	encoded, err := before.Bytes()
	require.Nil(b, err)

	target := MapPair{
		Key:   make([]byte, 1),
		Value: make([]byte, 1*1024),
	}

	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := target.FromBytesReusable(encoded, false)
		require.Nil(b, err)
	}

	assert.Equal(b, before.Key, target.Key)
	assert.Equal(b, before.Value, target.Value)
}
