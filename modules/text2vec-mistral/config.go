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

package modmistral

import (
	"context"

	"github.com/weaviate/weaviate/modules/text2vec-mistral/ent"

	"github.com/weaviate/weaviate/entities/models"
	"github.com/weaviate/weaviate/entities/modulecapabilities"
	"github.com/weaviate/weaviate/entities/moduletools"
	"github.com/weaviate/weaviate/entities/schema"
)

func (m *MistralModule) ClassConfigDefaults() map[string]interface{} {
	return map[string]interface{}{
		"vectorizeClassName": ent.DefaultVectorizeClassName,
		"baseURL":            ent.DefaultBaseURL,
		"model":              ent.DefaultMistralModel,
	}
}

func (m *MistralModule) PropertyConfigDefaults(
	dt *schema.DataType,
) map[string]interface{} {
	return map[string]interface{}{
		"skip":                  !ent.DefaultPropertyIndexed,
		"vectorizePropertyName": ent.DefaultVectorizePropertyName,
	}
}

func (m *MistralModule) ValidateClass(ctx context.Context,
	class *models.Class, cfg moduletools.ClassConfig,
) error {
	settings := ent.NewClassSettings(cfg)
	return settings.Validate(class)
}

var _ = modulecapabilities.ClassConfigurator(New())
