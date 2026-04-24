// POC: Namespace-aware Casbin matching for globally reusable roles.
// This file is throwaway — delete after validating results.
// Run: go test -v -run TestNamespace ./usecases/auth/authorization/rbac/

package rbac

import (
	"strings"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaviate/weaviate/usecases/auth/authorization"
	"github.com/weaviate/weaviate/usecases/auth/authorization/conv"
)

// This POC matches the current design:
//   - request objects are already resolved before Casbin (e.g. ABC@Movies)
//   - request namespace is passed separately as r.ns (e.g. ABC)
//   - role assignment is scoped via g = _, _, _
//   - global reusable roles can store namespace-relative collection patterns
//     such as Movies_.* without materializing one policy per namespace
//   - namespace-local roles can still store fully resolved policies such as
//     ABC@Movies and rely on the same matcher fast path
const NAMESPACE_POC_MODEL = `
[request_definition]
r = sub, obj, act, ns

[policy_definition]
p = sub, obj, act, dom, ns

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.ns) && namespaceAwareMatcher(r.obj, p.obj, r.ns) && regexMatch(r.act, p.act) && (p.ns == "" || p.ns == r.ns)
`

func newNamespacePOCEnforcer(t *testing.T) *casbin.SyncedCachedEnforcer {
	t.Helper()

	m, err := model.NewModelFromString(NAMESPACE_POC_MODEL)
	require.NoError(t, err)

	e, err := casbin.NewSyncedCachedEnforcer(m)
	require.NoError(t, err)
	e.SetExpireTime(time.Hour)
	e.AddFunction("namespaceAwareMatcher", namespaceAwareMatcherFunc)

	return e
}

func namespaceAwareMatcherFunc(args ...interface{}) (interface{}, error) {
	requestObj := args[0].(string)
	policyObj := args[1].(string)
	namespace := args[2].(string)

	return namespaceAwareMatcher(requestObj, policyObj, namespace), nil
}

func namespaceAwareMatcher(requestObj, policyObj, namespace string) bool {
	// Fast path:
	//   - non-namespaced requests behave exactly like today
	//   - already-resolved policies (e.g. ABC@Movies) also skip namespace injection
	if !needsNamespaceResolution(policyObj, namespace) {
		return WeaviateMatcher(requestObj, policyObj)
	}

	return WeaviateMatcher(requestObj, prefixCollectionSegment(policyObj, namespace))
}

func needsNamespaceResolution(policyObj, namespace string) bool {
	if namespace == "" || !strings.Contains(policyObj, "/collections/") {
		return false
	}

	segment, ok := collectionSegment(policyObj)
	if !ok {
		return false
	}

	return segment != "*" && !strings.Contains(segment, "@")
}

func prefixCollectionSegment(policyObj, namespace string) string {
	segmentStart, segmentEnd, ok := collectionSegmentBounds(policyObj)
	if !ok {
		return policyObj
	}

	segment := policyObj[segmentStart:segmentEnd]
	if segment == "*" || strings.Contains(segment, "@") {
		return policyObj
	}

	return policyObj[:segmentStart] + namespace + "@" + segment + policyObj[segmentEnd:]
}

func collectionSegment(policyObj string) (string, bool) {
	segmentStart, segmentEnd, ok := collectionSegmentBounds(policyObj)
	if !ok {
		return "", false
	}

	return policyObj[segmentStart:segmentEnd], true
}

func collectionSegmentBounds(policyObj string) (int, int, bool) {
	collectionMarker := "/collections/"
	markerIndex := strings.Index(policyObj, collectionMarker)
	if markerIndex == -1 {
		return 0, 0, false
	}

	segmentStart := markerIndex + len(collectionMarker)
	nextSlash := strings.Index(policyObj[segmentStart:], "/")
	if nextSlash == -1 {
		return 0, 0, false
	}

	segmentEnd := segmentStart + nextSlash
	return segmentStart, segmentEnd, true
}

func TestNamespaceModelSharedGlobalTemplateRole(t *testing.T) {
	e := newNamespacePOCEnforcer(t)

	sandboxRole := conv.PrefixRoleName("sandboxUser_role")
	abcUser := "db:abc_user"
	defUser := "db:def_user"

	// Shared role defined once with namespace-relative collection patterns.
	_, err := e.AddPolicy([]string{sandboxRole, conv.CasbinSchema("Movies_.*", "#"), "R", "schema", ""})
	require.NoError(t, err)
	_, err = e.AddPolicy([]string{sandboxRole, conv.CasbinData("Movies_.*", ".*", ".*"), "R", "data", ""})
	require.NoError(t, err)

	_, err = e.AddRoleForUser(abcUser, sandboxRole, "ABC")
	require.NoError(t, err)
	_, err = e.AddRoleForUser(defUser, sandboxRole, "DEF")
	require.NoError(t, err)

	tests := []struct {
		name     string
		user     string
		resource string
		verb     string
		ns       string
		expected bool
	}{
		{
			name:     "ABC user matches own resolved collection",
			user:     abcUser,
			resource: authorization.CollectionsMetadata("ABC@Movies_2025")[0],
			verb:     "R",
			ns:       "ABC",
			expected: true,
		},
		{
			name:     "ABC user matches own resolved object path",
			user:     abcUser,
			resource: authorization.Objects("ABC@Movies_2025", "tenant1", "obj1"),
			verb:     "R",
			ns:       "ABC",
			expected: true,
		},
		{
			name:     "DEF user reuses same role in DEF namespace",
			user:     defUser,
			resource: authorization.CollectionsMetadata("DEF@Movies_2025")[0],
			verb:     "R",
			ns:       "DEF",
			expected: true,
		},
		{
			name:     "ABC user cannot match DEF resource with ABC namespace",
			user:     abcUser,
			resource: authorization.CollectionsMetadata("DEF@Movies_2025")[0],
			verb:     "R",
			ns:       "ABC",
			expected: false,
		},
		{
			name:     "ABC user cannot match unnamespaced resource",
			user:     abcUser,
			resource: authorization.CollectionsMetadata("Movies_2025")[0],
			verb:     "R",
			ns:       "ABC",
			expected: false,
		},
		{
			name:     "ABC user cannot match other collection prefix",
			user:     abcUser,
			resource: authorization.CollectionsMetadata("ABC@Articles_2025")[0],
			verb:     "R",
			ns:       "ABC",
			expected: false,
		},
		{
			name:     "ABC user cannot reuse same role under DEF request namespace",
			user:     abcUser,
			resource: authorization.CollectionsMetadata("DEF@Movies_2025")[0],
			verb:     "R",
			ns:       "DEF",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := e.Enforce(tt.user, tt.resource, tt.verb, tt.ns)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, allowed, "Enforce(%q, %q, %q, ns=%q)", tt.user, tt.resource, tt.verb, tt.ns)
		})
	}
}

func TestNamespaceModelResolvedNamespacePolicy(t *testing.T) {
	e := newNamespacePOCEnforcer(t)

	nsRole := conv.PrefixRoleName("ABC@editor")
	nsUser := "db:abc_subuser"

	_, err := e.AddRoleForUser(nsUser, nsRole, "ABC")
	require.NoError(t, err)
	_, err = e.AddPolicy([]string{nsRole, conv.CasbinSchema("ABC@Movies", "#"), "R", "schema", "ABC"})
	require.NoError(t, err)
	_, err = e.AddPolicy([]string{nsRole, conv.CasbinData("ABC@Movies", ".*", ".*"), "R", "data", "ABC"})
	require.NoError(t, err)

	allowed, err := e.Enforce(nsUser, authorization.CollectionsMetadata("ABC@Movies")[0], "R", "ABC")
	require.NoError(t, err)
	assert.True(t, allowed, "resolved namespace policy should match directly")

	allowed, err = e.Enforce(nsUser, authorization.CollectionsMetadata("ABC@Movies")[0], "R", "DEF")
	require.NoError(t, err)
	assert.False(t, allowed, "resolved namespace policy should not match a different request namespace")

	allowed, err = e.Enforce(nsUser, authorization.CollectionsMetadata("DEF@Movies")[0], "R", "ABC")
	require.NoError(t, err)
	assert.False(t, allowed, "resolved namespace policy should not match a different resolved object")
}

func TestNamespaceModelResolvedPolicyFastPath(t *testing.T) {
	e := newNamespacePOCEnforcer(t)

	sandboxRole := conv.PrefixRoleName("sandboxUser_role")
	abcUser := "db:abc_user"

	_, err := e.AddRoleForUser(abcUser, sandboxRole, "ABC")
	require.NoError(t, err)
	_, err = e.AddPolicy([]string{sandboxRole, conv.CasbinSchema("ABC@Movies_.*", "#"), "R", "schema", ""})
	require.NoError(t, err)

	allowed, err := e.Enforce(abcUser, authorization.CollectionsMetadata("ABC@Movies_2025")[0], "R", "ABC")
	require.NoError(t, err)
	assert.True(t, allowed, "already-resolved policies should match directly without namespace injection")

	allowed, err = e.Enforce(abcUser, authorization.CollectionsMetadata("DEF@Movies_2025")[0], "R", "ABC")
	require.NoError(t, err)
	assert.False(t, allowed, "already-resolved policies should not be rewritten to another namespace")
}

func TestNamespaceModelNonNamespacedFastPath(t *testing.T) {
	e := newNamespacePOCEnforcer(t)

	legacyRole := conv.PrefixRoleName("legacy_reader")
	legacyUser := "db:legacy_user"

	_, err := e.AddRoleForUser(legacyUser, legacyRole, "")
	require.NoError(t, err)
	_, err = e.AddPolicy([]string{legacyRole, conv.CasbinSchema("Movies_.*", "#"), "R", "schema", ""})
	require.NoError(t, err)

	allowed, err := e.Enforce(legacyUser, authorization.CollectionsMetadata("Movies_2025")[0], "R", "")
	require.NoError(t, err)
	assert.True(t, allowed, "non-namespaced requests should behave like the current matcher")

	allowed, err = e.Enforce(legacyUser, authorization.CollectionsMetadata("ABC@Movies_2025")[0], "R", "")
	require.NoError(t, err)
	assert.False(t, allowed, "non-namespaced requests must not get namespace injection")
}

var namespaceMatcherResult bool

func BenchmarkNamespaceAwareMatcher_NonNamespacedFastPath(b *testing.B) {
	requestObj := authorization.CollectionsMetadata("Movies_2025")[0]
	policyObj := conv.CasbinSchema("Movies_.*", "#")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		namespaceMatcherResult = namespaceAwareMatcher(requestObj, policyObj, "")
	}
}

func BenchmarkNamespaceAwareMatcher_NamespaceTemplateResolution(b *testing.B) {
	requestObj := authorization.CollectionsMetadata("ABC@Movies_2025")[0]
	policyObj := conv.CasbinSchema("Movies_.*", "#")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		namespaceMatcherResult = namespaceAwareMatcher(requestObj, policyObj, "ABC")
	}
}
