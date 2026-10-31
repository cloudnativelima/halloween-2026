package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHauntedLoopSeparatesListenerBootstrapAndReady(t *testing.T) {
	config := hauntedConfig{
		warmupDuration:   80 * time.Millisecond,
		listenerDuration: 20 * time.Millisecond,
		listenerPhase:    "listener",
		bootstrapPhase:   "bootstrap",
		initializedPhase: "initialized",
	}
	for _, test := range []struct {
		name       string
		elapsed    time.Duration
		path       string
		wantStatus int
	}{
		{name: "listener answers liveness", elapsed: 0, path: "/healthz", wantStatus: http.StatusOK},
		{name: "listener is not ready", elapsed: 0, path: "/ready", wantStatus: http.StatusServiceUnavailable},
		{name: "bootstrap is not ready", elapsed: 40 * time.Millisecond, path: "/light", wantStatus: http.StatusServiceUnavailable},
		{name: "initialized service responds", elapsed: 100 * time.Millisecond, path: "/light", wantStatus: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			hauntedLoopHandler(time.Now().Add(-test.elapsed), config).ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("GET %s status = %d, want %d", test.path, recorder.Code, test.wantStatus)
			}
		})
	}
}

func TestCursedEndpointListenersHaveDifferentContracts(t *testing.T) {
	business, diagnostic := cursedEndpointHandlers(sealContract{
		BusinessStatus: "complete", BusinessSealed: true,
		DiagnosticStatus: "diagnostic", DiagnosticSealed: false,
	}, "canary", testLogger())
	for _, test := range []struct {
		name     string
		handler  http.Handler
		wantSeal bool
		wantText string
	}{
		{name: "business listener", handler: business, wantSeal: true, wantText: "complete"},
		{name: "diagnostic listener", handler: diagnostic, wantSeal: false, wantText: "diagnostic"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			cursedRequest := httptest.NewRequest(http.MethodGet, "/seal", nil)
			test.handler.ServeHTTP(recorder, cursedRequest)
			if recorder.Code != http.StatusOK {
				t.Fatalf("GET /seal status = %d, want 200", recorder.Code)
			}
			var got sealResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if got.Sealed != test.wantSeal || got.Status != test.wantText {
				t.Errorf("response = %+v, want sealed=%t status=%q", got, test.wantSeal, test.wantText)
			}
		})
	}
}

func TestHauntedProbeContractHasEnoughStartupBudgetAndActiveHealthChecks(t *testing.T) {
	ports := []containerPort{{Name: "http", ContainerPort: 8080}}
	valid := containerObject{
		Name: "haunted-loop", Ports: ports,
		StartupProbe:   httpProbe("/ready", `"http"`, 2, 35, 0),
		ReadinessProbe: httpProbe("/ready", `"http"`, 2, 1, 0),
		LivenessProbe:  httpProbe("/ready", `"http"`, 2, 2, 0),
	}
	if !hauntedProbesAreSafe(valid) {
		t.Fatal("a startup barrier on /ready with sufficient budget should pass")
	}
	valid.StartupProbe = httpProbe("/healthz", `"http"`, 2, 12, 0)
	if hauntedProbesAreSafe(valid) {
		t.Fatal("a startup probe that succeeds at listener start should not pass")
	}
	valid.StartupProbe = httpProbe("/ready", `"http"`, 2, 3, 0)
	if hauntedProbesAreSafe(valid) {
		t.Fatal("a startup probe without enough bootstrap budget should not pass")
	}
	valid.StartupProbe = httpProbe("/ready", `"http"`, 2, 35, 0)
	valid.LivenessProbe = httpProbe("/process-live", `"http"`, 2, 3, 0)
	if !hauntedProbesAreSafe(valid) {
		t.Fatal("a process-liveness endpoint with readiness kept active should pass")
	}
	valid.LivenessProbe = nil
	if hauntedProbesAreSafe(valid) {
		t.Fatal("removing liveness must not pass")
	}
}

func TestPodHasNoSecretInjection(t *testing.T) {
	container := containerObject{Name: auditAgentName}
	podSpec := podSpecObject{Containers: []containerObject{container}}
	if !podHasNoSecretInjection(podSpec, container) {
		t.Fatal("clean application Pod should pass")
	}

	podSpec.InitContainers = []containerObject{{Name: "archivist"}}
	if podHasNoSecretInjection(podSpec, container) {
		t.Fatal("an init container should not pass")
	}
	podSpec.InitContainers = nil
	podSpec.Volumes = []volumeObject{{Secret: &secretVolume{SecretName: supportSecretName}}}
	if podHasNoSecretInjection(podSpec, container) {
		t.Fatal("a Secret volume should not pass")
	}
	podSpec.Volumes = nil
	container.Env = []envVarObject{{Name: "SECRET", Value: "value"}}
	if podHasNoSecretInjection(podSpec, container) {
		t.Fatal("an environment variable should not pass")
	}
}

func TestAuditAttestationRequiresCleanAllowedConfigMap(t *testing.T) {
	attestation := auditAttestation{
		AuditLedgerReadable:    true,
		RestrictedLedgerDenied: true,
		ConfigMapListDenied:    true,
		SupportSecretDenied:    true,
		SecretListDenied:       true,
	}
	if attestation.complete() {
		t.Fatal("readable but contaminated ConfigMap should not complete the audit")
	}
	attestation.AuditLedgerClean = true
	if !attestation.complete() {
		t.Fatal("clean authorized ConfigMap and all permission checks should pass")
	}
}

func TestResolveTargetPortAcrossVersionedPods(t *testing.T) {
	stable := []containerObject{{Ports: []containerPort{{Name: "web", ContainerPort: 8080}, {Name: "admin", ContainerPort: 9090}}}}
	canary := []containerObject{{Ports: []containerPort{{Name: "web", ContainerPort: 9090}, {Name: "admin", ContainerPort: 8080}}}}
	if port, ok := resolveTargetPort(json.RawMessage(`"web"`), stable); !ok || port != 8080 {
		t.Fatalf("stable named port = (%d, %t), want (8080, true)", port, ok)
	}
	if port, ok := resolveTargetPort(json.RawMessage(`"web"`), canary); !ok || port != 9090 {
		t.Fatalf("canary named port = (%d, %t), want (9090, true)", port, ok)
	}
	if port, ok := resolveTargetPort(json.RawMessage(`8080`), canary); !ok || port != 8080 {
		t.Fatalf("numeric targetPort = (%d, %t), want (8080, true)", port, ok)
	}
	if _, ok := resolveTargetPort(json.RawMessage(`"missing"`), canary); ok {
		t.Fatal("unresolved named targetPort unexpectedly passed")
	}
}

func TestCursedBackendConfigCannotSpoofDiagnosticListener(t *testing.T) {
	container := containerObject{
		Env:     []envVarObject{{Name: "BACKEND_TRACK", Value: "canary"}},
		EnvFrom: []envFromObject{{}},
	}
	container.EnvFrom[0].ConfigMapRef.Name = cursedContractConfig
	if !cursedBackendConfigIsValid(container, "canary") {
		t.Fatal("expected backend config source and track should pass")
	}

	spoofed := container
	spoofed.Env = append(spoofed.Env, envVarObject{Name: "DIAGNOSTIC_SEALED", Value: "true"})
	if cursedBackendConfigIsValid(spoofed, "canary") {
		t.Fatal("a direct diagnostic contract override must not pass")
	}

	wrongTrack := container
	wrongTrack.Env = []envVarObject{{Name: "BACKEND_TRACK", Value: "stable"}}
	if cursedBackendConfigIsValid(wrongTrack, "canary") {
		t.Fatal("a backend with the wrong configured track must not pass")
	}

	wrongSource := container
	wrongSource.EnvFrom = nil
	if cursedBackendConfigIsValid(wrongSource, "canary") {
		t.Fatal("a backend that does not load the contract ConfigMap must not pass")
	}
}

func TestRoleHasOnlyNamedRead(t *testing.T) {
	good := policyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}, ResourceNames: []string{auditLedgerName}}
	if !roleHasOnlyNamedRead([]policyRule{good}, "configmaps", auditLedgerName) {
		t.Fatal("named ConfigMap get should pass")
	}
	bad := good
	bad.Verbs = []string{"get", "list"}
	if roleHasOnlyNamedRead([]policyRule{bad}, "configmaps", auditLedgerName) {
		t.Fatal("list permission unexpectedly passed")
	}
	bad = good
	bad.ResourceNames = nil
	if roleHasOnlyNamedRead([]policyRule{bad}, "configmaps", auditLedgerName) {
		t.Fatal("unnamed resource permission unexpectedly passed")
	}
	if roleHasOnlyNamedRead([]policyRule{good, good}, "configmaps", auditLedgerName) {
		t.Fatal("extra RBAC rule unexpectedly passed")
	}
}

func TestBindingSubjectsDetectNamespacedServiceAccountGroup(t *testing.T) {
	matched, broad := bindingSubjects(possessedAccountNamespace, auditAgentName, []roleSubject{{Kind: "Group", Name: "system:serviceaccounts:" + possessedAccountNamespace}})
	if !matched || !broad {
		t.Fatalf("namespace ServiceAccount group = (%t, %t), want (true, true)", matched, broad)
	}
	matched, broad = bindingSubjects(possessedAccountNamespace, auditAgentName, []roleSubject{{Kind: "ServiceAccount", Name: auditAgentName, Namespace: possessedAccountNamespace}})
	if !matched || broad {
		t.Fatalf("direct ServiceAccount = (%t, %t), want (true, false)", matched, broad)
	}
}

func TestAuditServiceAccountPoliciesRejectsInheritedGroupGrant(t *testing.T) {
	role := func(name, resource, object string) roleObject {
		value := roleObject{}
		value.Metadata.Name = name
		value.Rules = []policyRule{{APIGroups: []string{""}, Resources: []string{resource}, Verbs: []string{"get"}, ResourceNames: []string{object}}}
		return value
	}
	direct := func(sa, roleName string) roleBindingObject {
		binding := roleBindingObject{Subjects: []roleSubject{{Kind: "ServiceAccount", Name: sa, Namespace: possessedAccountNamespace}}}
		binding.RoleRef.APIGroup, binding.RoleRef.Kind, binding.RoleRef.Name = "rbac.authorization.k8s.io", "Role", roleName
		return binding
	}
	groupBinding := roleBindingObject{Subjects: []roleSubject{{Kind: "Group", Name: "system:serviceaccounts:" + possessedAccountNamespace}}}
	groupBinding.RoleRef.APIGroup, groupBinding.RoleRef.Kind, groupBinding.RoleRef.Name = "rbac.authorization.k8s.io", "Role", "support-reader"
	wrongAPIGroup := direct(supportAgentName, "support-reader")
	wrongAPIGroup.RoleRef.APIGroup = ""

	for _, test := range []struct {
		name    string
		binding roleBindingObject
		want    bool
	}{
		{name: "support subject explicitly names its identity", binding: direct(supportAgentName, "support-reader"), want: true},
		{name: "namespace group grants support Secret to audit identity", binding: groupBinding, want: false},
		{name: "RoleBinding has invalid API group", binding: wrongAPIGroup, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			rolesJSON, err := json.Marshal(roleList{Items: []roleObject{
				role("audit-reader", "configmaps", auditLedgerName),
				role("support-reader", "secrets", supportSecretName),
			}})
			if err != nil {
				t.Fatal(err)
			}
			bindings := roleBindingList{Items: []roleBindingObject{
				direct(auditAgentName, "audit-reader"), test.binding,
			}}
			bindingsJSON, err := json.Marshal(bindings)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case rbacResourcePath(possessedAccountNamespace, "roles"):
					_, _ = w.Write(rolesJSON)
				case rbacResourcePath(possessedAccountNamespace, "rolebindings"):
					_, _ = w.Write(bindingsJSON)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			kube := &kubeClient{baseURL: server.URL, namespace: possessedAccountNamespace, token: "test", client: server.Client()}
			got, err := auditServiceAccountPolicies(context.Background(), kube)
			if err != nil {
				t.Fatalf("auditServiceAccountPolicies: %v", err)
			}
			if got != test.want {
				t.Fatalf("policy audit = %t, want %t", got, test.want)
			}
		})
	}
}

func TestSupportSecretIsReadableDecodesOnlyExpectedValue(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("fictional-support-value"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != namespacedResourcePath(possessedAccountNamespace, "secrets", supportSecretName) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"payload":"`+payload+`"}}`)
	}))
	defer server.Close()
	kube := &kubeClient{baseURL: server.URL, namespace: possessedAccountNamespace, token: "test", client: server.Client()}
	readable, err := supportSecretIsReadable(context.Background(), kube)
	if err != nil || !readable {
		t.Fatalf("supportSecretIsReadable() = (%t, %v), want (true, nil)", readable, err)
	}
}

func TestIsForbiddenRequiresKubernetesForbiddenStatus(t *testing.T) {
	for _, test := range []struct {
		name string
		code int
		body string
		want bool
	}{
		{name: "403 forbidden", code: 403, body: `{"kind":"Status","status":"Failure","reason":"Forbidden","code":403}`, want: true},
		{name: "404 is not forbidden", code: 404, body: `{"kind":"Status","status":"Failure","reason":"NotFound","code":404}`},
		{name: "401 is not forbidden", code: 401, body: `{"kind":"Status","status":"Failure","reason":"Unauthorized","code":401}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.code)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()
			kube := &kubeClient{baseURL: server.URL, token: "test", client: server.Client()}
			got, err := kube.isForbidden(context.Background(), "/api/v1/namespaces/test/secrets/example")
			if err != nil || got != test.want {
				t.Fatalf("isForbidden() = (%t, %v), want (%t, nil)", got, err, test.want)
			}
		})
	}
}

func httpProbe(path, port string, period, failures, delay int) *probeObject {
	return &probeObject{HTTPGet: &httpGetProbe{Path: path, Port: json.RawMessage(port)}, PeriodSeconds: period, FailureThreshold: failures, InitialDelaySeconds: delay}
}

func testLogger() *log.Logger { return log.New(io.Discard, "", 0) }
