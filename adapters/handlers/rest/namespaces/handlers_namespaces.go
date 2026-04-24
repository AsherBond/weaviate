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

package namespaces

import (
	"fmt"
	"regexp"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus"

	cerrors "github.com/weaviate/weaviate/adapters/handlers/rest/errors"
	"github.com/weaviate/weaviate/adapters/handlers/rest/operations"
	nsops "github.com/weaviate/weaviate/adapters/handlers/rest/operations/namespaces"
	cmd "github.com/weaviate/weaviate/cluster/proto/api"
	"github.com/weaviate/weaviate/entities/models"
	"github.com/weaviate/weaviate/usecases/auth/authorization"
)

// NamespaceRaftGetter is the subset of cluster.Raft the handlers use. Keeping
// it narrow makes the unit tests easy to mock.
type NamespaceRaftGetter interface {
	AddNamespace(ns cmd.Namespace) error
	DeleteNamespace(name string) error
	GetNamespaces(names ...string) ([]cmd.Namespace, error)
}

type namespaceHandler struct {
	authorizer authorization.Authorizer
	raft       NamespaceRaftGetter
	logger     logrus.FieldLogger
}

// Name validation contract mirrors the one enforced on the apply side
// (cluster/namespaces). Kept local so handler-level rejections map to 422
// without a RAFT round-trip.
const (
	namespaceNameMinLength = 3
	namespaceNameMaxLength = 36
)

var (
	namespaceNameRegex = regexp.MustCompile(`^[a-z][a-z0-9]*$`)

	reservedNamespaceNames = map[string]struct{}{
		"admin":    {},
		"system":   {},
		"default":  {},
		"internal": {},
		"weaviate": {},
		"global":   {},
		"public":   {},
	}
)

// SetupHandlers wires the namespace handler methods into the generated REST
// API surface. Called from adapters/handlers/rest/configure_api.go next to the
// other SetupHandlers invocations.
func SetupHandlers(
	api *operations.WeaviateAPI,
	raft NamespaceRaftGetter,
	authorizer authorization.Authorizer,
	logger logrus.FieldLogger,
) {
	h := &namespaceHandler{
		authorizer: authorizer,
		raft:       raft,
		logger:     logger,
	}

	api.NamespacesCreateNamespaceHandler = nsops.CreateNamespaceHandlerFunc(h.createNamespace)
	api.NamespacesDeleteNamespaceHandler = nsops.DeleteNamespaceHandlerFunc(h.deleteNamespace)
	api.NamespacesGetNamespaceHandler = nsops.GetNamespaceHandlerFunc(h.getNamespace)
	api.NamespacesListNamespacesHandler = nsops.ListNamespacesHandlerFunc(h.listNamespaces)
}

func (h *namespaceHandler) validateNamespaceName(name string) error {
	if l := len(name); l < namespaceNameMinLength || l > namespaceNameMaxLength {
		return fmt.Errorf("namespace name %q must be %d-%d characters", name, namespaceNameMinLength, namespaceNameMaxLength)
	}
	if !namespaceNameRegex.MatchString(name) {
		return fmt.Errorf("namespace name %q must start with a lowercase letter and contain only lowercase letters and digits", name)
	}
	if _, reserved := reservedNamespaceNames[name]; reserved {
		return fmt.Errorf("namespace name %q is reserved", name)
	}
	return nil
}

// namespaceExists is a thin wrapper around GetNamespaces used by the create/
// delete pre-checks to decide 409/404 in the handler.
func (h *namespaceHandler) namespaceExists(name string) (bool, error) {
	got, err := h.raft.GetNamespaces(name)
	if err != nil {
		return false, err
	}
	return len(got) > 0, nil
}

func (h *namespaceHandler) createNamespace(params nsops.CreateNamespaceParams, principal *models.Principal) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	name := params.NamespaceID

	if err := h.authorizer.Authorize(ctx, principal, authorization.CREATE, authorization.Namespaces(name)...); err != nil {
		return nsops.NewCreateNamespaceForbidden().WithPayload(cerrors.ErrPayloadFromSingleErr(err))
	}

	if err := h.validateNamespaceName(name); err != nil {
		return nsops.NewCreateNamespaceUnprocessableEntity().WithPayload(cerrors.ErrPayloadFromSingleErr(err))
	}

	exists, err := h.namespaceExists(name)
	if err != nil {
		return nsops.NewCreateNamespaceInternalServerError().WithPayload(
			cerrors.ErrPayloadFromSingleErr(fmt.Errorf("checking namespace existence: %w", err)))
	}
	if exists {
		return nsops.NewCreateNamespaceConflict().WithPayload(
			cerrors.ErrPayloadFromSingleErr(fmt.Errorf("namespace %q already exists", name)))
	}

	if err := h.raft.AddNamespace(cmd.Namespace{Name: name}); err != nil {
		return nsops.NewCreateNamespaceInternalServerError().WithPayload(
			cerrors.ErrPayloadFromSingleErr(fmt.Errorf("creating namespace: %w", err)))
	}

	return nsops.NewCreateNamespaceCreated().WithPayload(&models.Namespace{Name: name})
}

func (h *namespaceHandler) getNamespace(params nsops.GetNamespaceParams, principal *models.Principal) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	name := params.NamespaceID

	if err := h.authorizer.Authorize(ctx, principal, authorization.READ, authorization.Namespaces(name)...); err != nil {
		return nsops.NewGetNamespaceForbidden().WithPayload(cerrors.ErrPayloadFromSingleErr(err))
	}

	got, err := h.raft.GetNamespaces(name)
	if err != nil {
		return nsops.NewGetNamespaceInternalServerError().WithPayload(
			cerrors.ErrPayloadFromSingleErr(fmt.Errorf("getting namespace: %w", err)))
	}
	if len(got) == 0 {
		return nsops.NewGetNamespaceNotFound().WithPayload(
			cerrors.ErrPayloadFromSingleErr(fmt.Errorf("namespace %q not found", name)))
	}

	return nsops.NewGetNamespaceOK().WithPayload(&models.Namespace{Name: got[0].Name})
}

func (h *namespaceHandler) deleteNamespace(params nsops.DeleteNamespaceParams, principal *models.Principal) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	name := params.NamespaceID

	if err := h.authorizer.Authorize(ctx, principal, authorization.DELETE, authorization.Namespaces(name)...); err != nil {
		return nsops.NewDeleteNamespaceForbidden().WithPayload(cerrors.ErrPayloadFromSingleErr(err))
	}

	// Pre-check for 404. The RAFT delete also errors on missing entries, but
	// the REST contract is "404 on not found"; pre-checking here keeps the
	// status decision in the handler and mirrors the 409 pre-check in
	// createNamespace. A concurrent delete between the pre-check and the
	// actual DeleteNamespace could surface as 500 instead of 204 for the
	// loser — acceptable (same observable outcome: the namespace is gone).
	exists, err := h.namespaceExists(name)
	if err != nil {
		return nsops.NewDeleteNamespaceInternalServerError().WithPayload(
			cerrors.ErrPayloadFromSingleErr(fmt.Errorf("checking namespace existence: %w", err)))
	}
	if !exists {
		return nsops.NewDeleteNamespaceNotFound().WithPayload(
			cerrors.ErrPayloadFromSingleErr(fmt.Errorf("namespace %q not found", name)))
	}

	if err := h.raft.DeleteNamespace(name); err != nil {
		return nsops.NewDeleteNamespaceInternalServerError().WithPayload(
			cerrors.ErrPayloadFromSingleErr(fmt.Errorf("deleting namespace: %w", err)))
	}

	return nsops.NewDeleteNamespaceNoContent()
}

// listNamespaces never returns 403. Callers without any applicable
// manage_namespaces permission see an empty list, matching the listRoles
// convention so RBAC UIs can render a consistent empty state.
func (h *namespaceHandler) listNamespaces(params nsops.ListNamespacesParams, principal *models.Principal) middleware.Responder {
	ctx := params.HTTPRequest.Context()

	all, err := h.raft.GetNamespaces()
	if err != nil {
		return nsops.NewListNamespacesInternalServerError().WithPayload(
			cerrors.ErrPayloadFromSingleErr(fmt.Errorf("listing namespaces: %w", err)))
	}
	if len(all) == 0 {
		return nsops.NewListNamespacesOK().WithPayload([]*models.Namespace{})
	}

	resources := make([]string, len(all))
	for i, ns := range all {
		resources[i] = authorization.Namespaces(ns.Name)[0]
	}

	allowed, err := h.authorizer.FilterAuthorizedResources(ctx, principal, authorization.READ, resources...)
	if err != nil {
		return nsops.NewListNamespacesInternalServerError().WithPayload(
			cerrors.ErrPayloadFromSingleErr(fmt.Errorf("filtering authorized namespaces: %w", err)))
	}

	allowedSet := make(map[string]struct{}, len(allowed))
	for _, r := range allowed {
		allowedSet[r] = struct{}{}
	}

	out := make([]*models.Namespace, 0, len(allowed))
	for _, ns := range all {
		if _, ok := allowedSet[authorization.Namespaces(ns.Name)[0]]; ok {
			out = append(out, &models.Namespace{Name: ns.Name})
		}
	}
	return nsops.NewListNamespacesOK().WithPayload(out)
}
