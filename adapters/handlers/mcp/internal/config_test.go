//                           _       _
// __      _____  __ ___   ___  __ _| |_ ___
// \ \ /\ / / _ \/ _` \ \ / / |/ _` | __/ _ \
//  \ V  V /  __/ (_| |\ V /| | (_| | ||  __/
//   \_/\_/ \___|\__,_| \_/ |_|\__,_|\__\___|
//
//  Copyright © 2016 - 2026 Weaviate B.V. All rights reserved.
//
//  CONTACT: hello@weaviate.io
//

package internal

import (
	"encoding/json"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDescription(t *testing.T) {
	configs := map[string]ToolConfig{
		"my-tool": {Description: "custom desc"},
	}

	t.Run("returns custom description when present", func(t *testing.T) {
		assert.Equal(t, "custom desc", GetDescription(configs, "my-tool", "default"))
	})

	t.Run("returns default when tool not in config", func(t *testing.T) {
		assert.Equal(t, "default", GetDescription(configs, "other-tool", "default"))
	})

	t.Run("returns default when configs is nil", func(t *testing.T) {
		assert.Equal(t, "default", GetDescription(nil, "my-tool", "default"))
	})

	t.Run("returns default when description is empty", func(t *testing.T) {
		configs := map[string]ToolConfig{"my-tool": {}}
		assert.Equal(t, "default", GetDescription(configs, "my-tool", "default"))
	})
}

func TestApplySchemaDescriptions(t *testing.T) {
	makeSchema := func(props map[string]any) json.RawMessage {
		schema := map[string]any{"type": "object", "properties": props}
		b, _ := json.Marshal(schema)
		return b
	}

	t.Run("overrides argument descriptions", func(t *testing.T) {
		tool := mcp.Tool{
			RawInputSchema: makeSchema(map[string]any{
				"query":           map[string]any{"type": "string", "description": "original"},
				"collection_name": map[string]any{"type": "string", "description": "original"},
			}),
		}
		configs := map[string]ToolConfig{
			"my-tool": {
				Arguments: map[string]string{
					"query": "custom query description",
				},
			},
		}

		ApplySchemaDescriptions(&tool, "my-tool", configs)

		var schema map[string]any
		require.NoError(t, json.Unmarshal(tool.RawInputSchema, &schema))
		props := schema["properties"].(map[string]any)
		assert.Equal(t, "custom query description", props["query"].(map[string]any)["description"])
		assert.Equal(t, "original", props["collection_name"].(map[string]any)["description"])
	})

	t.Run("overrides response descriptions", func(t *testing.T) {
		tool := mcp.Tool{
			RawOutputSchema: makeSchema(map[string]any{
				"results": map[string]any{"type": "array", "description": "original"},
			}),
		}
		configs := map[string]ToolConfig{
			"my-tool": {
				Response: map[string]string{
					"results": "custom results description",
				},
			},
		}

		ApplySchemaDescriptions(&tool, "my-tool", configs)

		var schema map[string]any
		require.NoError(t, json.Unmarshal(tool.RawOutputSchema, &schema))
		props := schema["properties"].(map[string]any)
		assert.Equal(t, "custom results description", props["results"].(map[string]any)["description"])
	})

	t.Run("no-op when tool not in config", func(t *testing.T) {
		original := makeSchema(map[string]any{
			"query": map[string]any{"type": "string", "description": "original"},
		})
		tool := mcp.Tool{RawInputSchema: json.RawMessage(append([]byte{}, original...))}

		ApplySchemaDescriptions(&tool, "other-tool", map[string]ToolConfig{
			"my-tool": {Arguments: map[string]string{"query": "custom"}},
		})

		assert.JSONEq(t, string(original), string(tool.RawInputSchema))
	})

	t.Run("no-op when configs is nil", func(t *testing.T) {
		original := makeSchema(map[string]any{
			"query": map[string]any{"type": "string", "description": "original"},
		})
		tool := mcp.Tool{RawInputSchema: json.RawMessage(append([]byte{}, original...))}

		ApplySchemaDescriptions(&tool, "my-tool", nil)

		assert.JSONEq(t, string(original), string(tool.RawInputSchema))
	})

	t.Run("no-op when schema is nil", func(t *testing.T) {
		tool := mcp.Tool{}
		configs := map[string]ToolConfig{
			"my-tool": {Arguments: map[string]string{"query": "custom"}},
		}

		ApplySchemaDescriptions(&tool, "my-tool", configs)

		assert.Nil(t, tool.RawInputSchema)
	})

	t.Run("ignores arguments not in schema", func(t *testing.T) {
		tool := mcp.Tool{
			RawInputSchema: makeSchema(map[string]any{
				"query": map[string]any{"type": "string", "description": "original"},
			}),
		}
		configs := map[string]ToolConfig{
			"my-tool": {
				Arguments: map[string]string{
					"nonexistent": "should be ignored",
				},
			},
		}

		ApplySchemaDescriptions(&tool, "my-tool", configs)

		var schema map[string]any
		require.NoError(t, json.Unmarshal(tool.RawInputSchema, &schema))
		props := schema["properties"].(map[string]any)
		assert.Equal(t, "original", props["query"].(map[string]any)["description"])
		_, exists := props["nonexistent"]
		assert.False(t, exists)
	})
}

func TestToToolConfigMap(t *testing.T) {
	t.Run("returns nil for nil config", func(t *testing.T) {
		var c *Config
		assert.Nil(t, c.ToToolConfigMap())
	})

	t.Run("returns tools map", func(t *testing.T) {
		c := &Config{
			Tools: map[string]ToolConfig{
				"tool-a": {Description: "desc a"},
			},
		}
		m := c.ToToolConfigMap()
		assert.Equal(t, "desc a", m["tool-a"].Description)
	})
}
