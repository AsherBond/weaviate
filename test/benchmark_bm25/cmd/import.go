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

package cmd

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/weaviate/weaviate-go-client/v5/weaviate/batch"
	"github.com/weaviate/weaviate/entities/models"
	"github.com/weaviate/weaviate/test/benchmark_bm25/lib"
)

func init() {
	rootCmd.AddCommand(importCmd)
	importCmd.PersistentFlags().IntVarP(&BatchSize, "batch-size", "b", DefaultBatchSize, "number of objects in a single import batch")
	importCmd.PersistentFlags().IntVarP(&MultiplyProperties, "multiply-properties", "m", DefaultMultiplyProperties, "create artifical copies of real properties by setting a value larger than 1. The properties have identical contents, so it won't alter results, but leads to many more calculations.")
	importCmd.PersistentFlags().BoolVarP(&Vectorizer, "vectorizer", "v", DefaultVectorizer, "Vectorize import data with default vectorizer")
	importCmd.PersistentFlags().IntVarP(&QueriesCount, "count", "c", DefaultQueriesCount, "run only the specified amount of queries, negative numbers mean unlimited")
	importCmd.PersistentFlags().IntVarP(&FilterObjectPercentage, "filter", "f", DefaultFilterObjectPercentage, "The given percentage of objects are filtered out. Off by default, use <=0 to disable")
	importCmd.PersistentFlags().Float32VarP(&Alpha, "alpha", "a", DefaultAlpha, "Weighting for keyword vs vector search. Alpha = 0 (Default) is pure BM25 search.")
	importCmd.PersistentFlags().StringVarP(&Ranking, "ranking", "r", DefaultRanking, "Which ranking algorithm should be used for hybrid search, rankedFusion (default) and relativeScoreFusion.")
	importCmd.PersistentFlags().IntVarP(&QueriesInterval, "query-interval", "i", DefaultQueriesInterval, "run queries every this number of inserts")
	importCmd.PersistentFlags().IntVarP(&Limit, "limit", "l", DefaultLimit, "Limit the number of results returned by the query")
	importCmd.PersistentFlags().BoolVarP(&AdditionalExplanations, "additional-explanations", "e", DefaultAdditionalExplanations, "Request additional explanations for the query results")
	importCmd.PersistentFlags().BoolVarP(&PrintDetailedResults, "print-detailed-results", "p", DefaultPrintDetailedResults, "Print detailed results")
}

func parseData(data []lib.Corpus, datasetId string, batch *batch.ObjectsBatcher, i int) int {
	total := 0
	for _, corp := range data {
		index := i + total
		id := uuid.MustParse(fmt.Sprintf("%032x", index)).String()
		props := map[string]interface{}{
			"modulo_10":   index % 10,
			"modulo_100":  index % 100,
			"modulo_1000": index % 1000,
		}

		for key, value := range corp {
			props[key] = value
		}

		batch.WithObjects(&models.Object{
			ID:         strfmt.UUID(id),
			Class:      lib.ClassNameFromDatasetID(datasetId),
			Properties: props,
		})

		total++
	}
	return total
}

type IndexingExperimentResult struct {
	// The name of the dataset
	Dataset string
	// The number of objects in the dataset
	Objects int
	// The batch size used for importing
	MultiplyProperties int
	// Docs where vectorized
	Vectorize bool
	// The time it took to import the dataset
	ImportTime float64
	// Average time to import 1000 objects
	ImportTimePer1000 float64
	// Objects per second
	ObjectsPerSecond float64
}

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a dataset (or multiple datasets) into Weaviate",

	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := lib.ClientFromOrigin(Origin)
		if err != nil {
			return err
		}

		ok, err := client.Misc().LiveChecker().Do(context.Background())
		if err != nil {
			return fmt.Errorf("weaviate is not ready at %v: %w", Origin, err)
		}

		if !ok {
			return fmt.Errorf("weaviate is not ready")
		}

		datasets, err := lib.ParseDatasetConfig(DatasetConfigPath)
		if err != nil {
			return fmt.Errorf("parse dataset cfg file: %w", err)
		}

		//if err := client.Schema().AllDeleter().Do(context.Background()); err != nil {
		//	return fmt.Errorf("clear schema prior to import: %w", err)
		//}

		experimentResults := make([]IndexingExperimentResult, len(datasets.Datasets))
		queryResults := make([]*QueryExperimentResult, 0)

		for di, dataset := range datasets.Datasets {

			// delete the class if it exists
			if err := client.Schema().ClassDeleter().WithClassName(lib.ClassNameFromDatasetID(dataset.ID)).Do(context.Background()); err != nil {
				return fmt.Errorf("delete class for %s: %w", dataset, err)
			}

			if err := client.Schema().ClassCreator().
				WithClass(lib.SchemaFromDataset(dataset, Vectorizer)).
				Do(context.Background()); err != nil {
				return fmt.Errorf("create schema for %s: %w", dataset, err)
			}
			log.Print("importing dataset " + dataset.ID)
			queries := make([]lib.Query, 0)
			if QueriesInterval != -1 {
				log.Print("parse queries")
				queries, err = lib.ParseQueries(dataset, QueriesCount)
				if err != nil {
					return err
				}
				log.Print("queries parsed")
			}

			start := time.Now()
			startBatch := time.Now()
			batch := client.Batch().ObjectsBatcher()

			indexCount := 0

			c, err := lib.ParseCorpi(dataset, MultiplyProperties)
			if err != nil {
				return err
			}

			i := 0
			for c.Next(BatchSize) == nil {
				data := c.Data

				if len(data) == 0 {
					break
				}
				parsedCount := parseData(data, dataset.ID, batch, i)
				i += parsedCount
				indexCount += parsedCount

				if indexCount%BatchSize == 0 {
					br, err := batch.Do(context.Background())
					if err != nil {
						return fmt.Errorf("batch %d: %w", indexCount, err)
					}

					if err := lib.HandleBatchResponse(br); err != nil {
						return err
					}
				}

				if indexCount%BatchSize == 0 {
					totalTimeBatch := time.Since(startBatch).Seconds()
					totalTime := time.Since(start).Seconds()
					startBatch = time.Now()
					log.Printf("imported %d objects in %.3f, time per 1k objects: %.3f, objects per second: %.0f", indexCount, totalTimeBatch, totalTime/float64(indexCount)*1000, float64(indexCount)/totalTime)
				}

				if QueriesInterval > 0 && indexCount%QueriesInterval == 0 {
					result, err := query(client, queries, dataset, indexCount)
					if err != nil {
						return fmt.Errorf("query: %w", err)
					}
					queryResults = append(queryResults, result)

				}
			}

			if len(c.Data) != 0 {
				data := c.Data
				parsedCount := parseData(data, dataset.ID, batch, i)
				i += parsedCount
				indexCount += parsedCount
				// we need to send one final batch
				br, err := batch.Do(context.Background())
				if err != nil {
					return fmt.Errorf("final batch: %w", err)
				}
				if err := lib.HandleBatchResponse(br); err != nil {
					return err
				}
				totalTimeBatch := time.Since(startBatch).Seconds()
				totalTime := time.Since(start).Seconds()
				log.Printf("imported %d objects in %.3f, time per 1k objects: %.3f, objects per second: %.0f", indexCount, totalTimeBatch, totalTime/float64(indexCount)*1000, float64(indexCount)/totalTime)
			}

			totalTime := time.Since(start).Seconds()
			log.Printf("importing finished %d objects in %.3f, time per 1k objects: %.3f, objects per second: %.0f", indexCount, totalTime, totalTime/float64(indexCount)*1000, float64(indexCount)/totalTime)

			if QueriesInterval != -1 && indexCount%QueriesInterval != 0 {
				// run queries after full import
				result, err := query(client, queries, dataset, indexCount)
				if err != nil {
					return fmt.Errorf("query: %w", err)
				}
				queryResults = append(queryResults, result)
			}

			experimentResults[di] = IndexingExperimentResult{
				Dataset:            dataset.ID,
				Objects:            indexCount,
				MultiplyProperties: MultiplyProperties,
				Vectorize:          Vectorizer,
				ImportTime:         time.Since(start).Seconds(),
				ImportTimePer1000:  time.Since(start).Seconds() / float64(indexCount) * 1000,
				ObjectsPerSecond:   float64(indexCount) / time.Since(start).Seconds(),
			}
		}
		// pretty print results fas TSV
		fmt.Printf("\nIndexing Results:\n")
		fmt.Printf("Dataset\tObjects\tMultiplyProperties\tVectorizer\tImportTime\tImportTimePer1000\tObjectsPerSecond\n")
		for _, result := range experimentResults {
			fmt.Printf("%s\t%d\t%d\t%t\t%.3f\t%.3f\t%.0f\n", result.Dataset, result.Objects, result.MultiplyProperties, result.Vectorize, result.ImportTime, result.ImportTimePer1000, result.ObjectsPerSecond)
		}

		fmt.Printf("\nQuery Results:\n")
		fmt.Printf("Dataset\tObjects\tQueries\tFilterObjectPercentage\tAlpha\tRanking\tQueryTime\tQueryTimePer1000\tQueriesPerSecond\tQueryTimePer1000000Documents\tMin\tMax\tP50\tP90\tP99\tnDCG\tP@1\tP@5\n")
		for _, result := range queryResults {
			ranking, _ := strconv.ParseFloat(result.Ranking, 64) // Convert result.Ranking to float64
			fmt.Printf("%s\t%d\t%d\t%d\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\t%.3f\n", result.Dataset, result.Objects, result.Queries, result.FilterObjectPercentage, result.Alpha, ranking, result.TotalQueryTime, result.AvgQueryTime.Seconds(), result.QueriesPerSecond, result.QueryTimePer1000000Documents, float32(result.Min.Milliseconds())/1000.0, float32(result.Max.Milliseconds())/1000.0, float32(result.P50.Milliseconds())/1000.0, float32(result.P90.Milliseconds())/1000.0, float32(result.P99.Milliseconds())/1000.0, result.Scores.CurrentNDCG(), result.Scores.CurrentPrecisionAt1(), result.Scores.CurrentPrecisionAt5())
		}

		return nil
	},
}
