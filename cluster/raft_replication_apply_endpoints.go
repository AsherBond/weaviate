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

package cluster

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-openapi/strfmt"
	"github.com/weaviate/weaviate/cluster/proto/api"
	"github.com/weaviate/weaviate/cluster/replication"
	replicationTypes "github.com/weaviate/weaviate/cluster/replication/types"
)

func (s *Raft) ReplicationReplicateReplica(ctx context.Context, uuid strfmt.UUID, sourceNode string, sourceCollection string, sourceShard string, targetNode string, transferType string) error {
	req := &api.ReplicationReplicateShardRequest{
		Version:          api.ReplicationCommandVersionV0,
		SourceNode:       sourceNode,
		SourceCollection: sourceCollection,
		SourceShard:      sourceShard,
		TargetNode:       targetNode,
		Uuid:             uuid,
		TransferType:     transferType,
	}

	if err := replication.ValidateReplicationReplicateShard(s.SchemaReader(), req); err != nil {
		return fmt.Errorf("%w: %w", replicationTypes.ErrInvalidRequest, err)
	}

	subCommand, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	command := &api.ApplyRequest{
		Type:       api.ApplyRequest_TYPE_REPLICATION_REPLICATE,
		SubCommand: subCommand,
	}
	if _, err := s.Execute(ctx, command); err != nil {
		return err
	}
	return nil
}

func (s *Raft) ReplicationUpdateReplicaOpStatus(ctx context.Context, id uint64, state api.ShardReplicationState) error {
	req := &api.ReplicationUpdateOpStateRequest{
		Version: api.ReplicationCommandVersionV0,
		Id:      id,
		State:   state,
	}

	subCommand, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	command := &api.ApplyRequest{
		Type:       api.ApplyRequest_TYPE_REPLICATION_REPLICATE_UPDATE_STATE,
		SubCommand: subCommand,
	}
	if _, err := s.Execute(ctx, command); err != nil {
		return err
	}
	return nil
}

func (s *Raft) ReplicationRegisterError(ctx context.Context, id uint64, errorToRegister string) error {
	req := &api.ReplicationRegisterErrorRequest{
		Version: api.ReplicationCommandVersionV0,
		Id:      id,
		Error:   errorToRegister,
	}

	subCommand, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	command := &api.ApplyRequest{
		Type:       api.ApplyRequest_TYPE_REPLICATION_REPLICATE_REGISTER_ERROR,
		SubCommand: subCommand,
	}
	if _, err := s.Execute(ctx, command); err != nil {
		return err
	}
	return nil
}

func (s *Raft) ReplicationCancellationComplete(ctx context.Context, id uint64) error {
	req := &api.ReplicationCancellationCompleteRequest{
		Version: api.ReplicationCommandVersionV0,
		Id:      id,
	}

	subCommand, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	command := &api.ApplyRequest{
		Type:       api.ApplyRequest_TYPE_REPLICATION_REPLICATE_CANCELLATION_COMPLETE,
		SubCommand: subCommand,
	}
	if _, err := s.Execute(ctx, command); err != nil {
		return err
	}
	return nil
}

func (s *Raft) CancelReplication(ctx context.Context, uuid strfmt.UUID) error {
	req := &api.ReplicationCancelRequest{
		Version: api.ReplicationCommandVersionV0,
		Uuid:    uuid,
	}

	subCommand, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	command := &api.ApplyRequest{
		Type:       api.ApplyRequest_TYPE_REPLICATION_REPLICATE_CANCEL,
		SubCommand: subCommand,
	}
	if _, err := s.Execute(ctx, command); err != nil {
		return err
	}
	return nil
}

func (s *Raft) DeleteReplication(ctx context.Context, uuid strfmt.UUID) error {
	req := &api.ReplicationDeleteRequest{
		Version: api.ReplicationCommandVersionV0,
		Uuid:    uuid,
	}

	subCommand, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	command := &api.ApplyRequest{
		Type:       api.ApplyRequest_TYPE_REPLICATION_REPLICATE_DELETE,
		SubCommand: subCommand,
	}
	if _, err := s.Execute(ctx, command); err != nil {
		return err
	}
	return nil
}

func (s *Raft) ReplicationRemoveReplicaOp(ctx context.Context, id uint64) error {
	req := &api.ReplicationRemoveOpRequest{
		Version: api.ReplicationCommandVersionV0,
		Id:      id,
	}

	subCommand, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	command := &api.ApplyRequest{
		Type:       api.ApplyRequest_TYPE_REPLICATION_REPLICATE_REMOVE,
		SubCommand: subCommand,
	}
	if _, err := s.Execute(ctx, command); err != nil {
		return err
	}
	return nil
}

func (s *Raft) DeleteAllReplications(ctx context.Context) error {
	req := &api.ReplicationDeleteAllRequest{
		Version: api.ReplicationCommandVersionV0,
	}

	subCommand, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	command := &api.ApplyRequest{
		Type:       api.ApplyRequest_TYPE_REPLICATION_REPLICATE_DELETE_ALL,
		SubCommand: subCommand,
	}
	if _, err := s.Execute(ctx, command); err != nil {
		return err
	}
	return nil
}

func (s *Raft) DeleteReplicationsByCollection(ctx context.Context, collection string) error {
	req := &api.ReplicationsDeleteByCollectionRequest{
		Version:    api.ReplicationCommandVersionV0,
		Collection: collection,
	}

	subCommand, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	command := &api.ApplyRequest{
		Type:       api.ApplyRequest_TYPE_REPLICATION_REPLICATE_DELETE_BY_COLLECTION,
		SubCommand: subCommand,
	}
	if _, err := s.Execute(ctx, command); err != nil {
		return err
	}
	return nil
}

func (s *Raft) DeleteReplicationsByTenants(ctx context.Context, collection string, tenants []string) error {
	req := &api.ReplicationsDeleteByTenantsRequest{
		Version:    api.ReplicationCommandVersionV0,
		Collection: collection,
		Tenants:    tenants,
	}

	subCommand, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	command := &api.ApplyRequest{
		Type:       api.ApplyRequest_TYPE_REPLICATION_REPLICATE_DELETE_BY_TENANTS,
		SubCommand: subCommand,
	}
	if _, err := s.Execute(ctx, command); err != nil {
		return err
	}
	return nil
}

func (s *Raft) ReplicationStoreSchemaVersion(ctx context.Context, id uint64, schemaVersion uint64) error {
	req := &api.ReplicationStoreSchemaVersionRequest{
		Version:       api.ReplicationCommandVersionV0,
		SchemaVersion: schemaVersion,
		Id:            id,
	}

	subCommand, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	command := &api.ApplyRequest{
		Type:       api.ApplyRequest_TYPE_REPLICATION_REGISTER_SCHEMA_VERSION,
		SubCommand: subCommand,
	}
	if _, err := s.Execute(ctx, command); err != nil {
		return err
	}
	return nil
}
