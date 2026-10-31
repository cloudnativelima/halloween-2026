//go:generate go run decode.go /run/secrets/flag-seed /src/challenge-data/seed

package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	modeHauntedLoop               = "haunted-loop"
	modeBackoffWatcher            = "backoff-watcher"
	modeCursedEndpoints           = "cursed-endpoints"
	modeEndpointWatcher           = "endpoint-watcher"
	modeAuditAgent                = "audit-agent"
	modeSupportAgent              = "support-agent"
	modePossessionAuditor         = "possession-auditor"
	hauntedLoopContainerName      = "haunted-loop"
	hauntedLoopNamespace          = "haunted-loop"
	hauntedLoopService            = "haunted-loop"
	hauntedRuntimeConfig          = "haunted-runtime"
	hauntedPhasesConfig           = "haunted-phases"
	hauntedShadowConfig           = "haunted-shadow-clock"
	hauntedWarmupSeconds          = 37
	hauntedListenerSeconds        = 4
	cursedEndpointsNamespace      = "cursed-endpoints"
	cursedEndpointsService        = "cursed-api"
	cursedBackendSelector         = "app=spectral-backend"
	cursedStableDeployment        = "spectral-stable"
	cursedCanaryDeployment        = "spectral-canary"
	cursedContractConfig          = "seal-contract"
	cursedStableService           = "spectral-stable-check"
	cursedCanaryService           = "spectral-canary-check"
	possessedAccountNamespace     = "possessed-sa"
	auditAgentName                = "audit-agent"
	supportAgentName              = "support-agent"
	possessionObserverName        = "possession-observer"
	supportAgentService           = "support-agent"
	auditLedgerName               = "audit-ledger"
	restrictedLedgerName          = "restricted-ledger"
	supportSecretName             = "support-secret"
	serviceAccountDirectory       = "/var/run/secrets/kubernetes.io/serviceaccount"
	loopStartupMargin             = 2 * time.Second
	loopStableDuration            = 60 * time.Second
	verificationInterval          = 2 * time.Second
	verificationSuccessesRequired = 3
	maxResponseBytes              = 1 << 20
)

//go:embed challenge-data/*
var challengeData embed.FS

const flagDomain = "cloudnativelima/kubectl-exorcise-2026/2026/"

func deriveFlag(challenge string) (string, error) {
	seed, err := challengeData.ReadFile("challenge-data/seed")
	if err != nil {
		return "", fmt.Errorf("read embedded challenge data: %w", err)
	}
	if len(seed) != 32 {
		return "", fmt.Errorf("embedded challenge data has invalid length %d", len(seed))
	}

	mac := hmac.New(sha256.New, seed)
	_, _ = io.WriteString(mac, flagDomain+challenge)
	identifier := hex.EncodeToString(mac.Sum(nil)[:16])
	return "EXORCISE2026{" + identifier + "}", nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := log.New(os.Stderr, "exorcise: ", log.LstdFlags)
	if err := run(ctx, os.Args[1:], os.Stdout, logger); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer, logger *log.Logger) error {
	if len(args) != 1 {
		return errors.New("usage: exorcise <mode>")
	}

	switch args[0] {
	case modeHauntedLoop:
		return runHauntedLoop(ctx, logger)
	case modeBackoffWatcher:
		return runBackoffWatcher(ctx, stdout, logger)
	case modeCursedEndpoints:
		return runCursedEndpoints(ctx, logger)
	case modeEndpointWatcher:
		return runEndpointWatcher(ctx, stdout, logger)
	case modeAuditAgent:
		return runAuditAgent(ctx, logger)
	case modeSupportAgent:
		return runSupportAgent(ctx, logger)
	case modePossessionAuditor:
		return runPossessionAuditor(ctx, stdout, logger)
	default:
		return fmt.Errorf("unknown mode %q", args[0])
	}
}

func runHauntedLoop(ctx context.Context, logger *log.Logger) error {
	config, err := hauntedConfigFromEnv()
	if err != nil {
		return err
	}
	startedAt := time.Now()
	logger.Printf("haunted loop phase: %s", hauntedPhase(startedAt, config, time.Now()))
	go logHauntedPhases(ctx, startedAt, config, logger)

	return serveHTTP(ctx, logger, &http.Server{
		Addr:              ":8080",
		Handler:           hauntedLoopHandler(startedAt, config),
		ReadHeaderTimeout: 5 * time.Second,
	})
}

type hauntedConfig struct {
	warmupDuration   time.Duration
	listenerDuration time.Duration
	listenerPhase    string
	bootstrapPhase   string
	initializedPhase string
}

func hauntedConfigFromEnv() (hauntedConfig, error) {
	warmupSeconds, err := requiredPositiveEnv("WARMUP_SECONDS", hauntedWarmupSeconds)
	if err != nil {
		return hauntedConfig{}, err
	}
	listenerSeconds, err := requiredPositiveEnv("LISTENER_SECONDS", hauntedListenerSeconds)
	if err != nil {
		return hauntedConfig{}, err
	}
	if listenerSeconds >= warmupSeconds {
		return hauntedConfig{}, errors.New("LISTENER_SECONDS must be less than WARMUP_SECONDS")
	}

	config := hauntedConfig{
		warmupDuration:   time.Duration(warmupSeconds) * time.Second,
		listenerDuration: time.Duration(listenerSeconds) * time.Second,
		listenerPhase:    envOrDefault("PHASE_LISTENER", "HTTP listener active"),
		bootstrapPhase:   envOrDefault("PHASE_BOOTSTRAP", "bootstrap in progress"),
		initializedPhase: envOrDefault("PHASE_INITIALIZED", "application initialized"),
	}
	return config, nil
}

func requiredPositiveEnv(name string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds < 1 || seconds > 120 {
		return 0, fmt.Errorf("%s must be an integer from 1 to 120", name)
	}
	return seconds, nil
}

func envOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func hauntedLoopHandler(startedAt time.Time, config hauntedConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		phase := hauntedPhase(startedAt, config, time.Now())
		ready := phase == config.initializedPhase
		switch r.URL.Path {
		case "/healthz", "/process-live":
			writeJSON(w, http.StatusOK, map[string]string{"alive": "true", "phase": phase})
		case "/ready":
			writeJSON(w, readinessStatus(ready), map[string]any{"ready": ready, "phase": phase})
		case "/light":
			if !ready {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false, "phase": phase})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"light": "lit"})
		default:
			http.NotFound(w, r)
		}
	})
}

func hauntedPhase(startedAt time.Time, config hauntedConfig, now time.Time) string {
	elapsed := now.Sub(startedAt)
	switch {
	case elapsed < config.listenerDuration:
		return config.listenerPhase
	case elapsed < config.warmupDuration:
		return config.bootstrapPhase
	default:
		return config.initializedPhase
	}
}

func logHauntedPhases(ctx context.Context, startedAt time.Time, config hauntedConfig, logger *log.Logger) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastPhase := config.listenerPhase

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			phase := hauntedPhase(startedAt, config, time.Now())
			if phase != lastPhase {
				logger.Printf("haunted loop phase: %s", phase)
				lastPhase = phase
			}
			if phase == config.initializedPhase {
				return
			}
		}
	}
}

func runCursedEndpoints(ctx context.Context, logger *log.Logger) error {
	contract, err := sealContractFromEnv()
	if err != nil {
		return err
	}
	track := envOrDefault("BACKEND_TRACK", "unassigned")
	logger.Printf("starting cursed backend track=%s", track)
	business, diagnostic := cursedEndpointHandlers(contract, track, logger)
	return serveHTTP(ctx, logger,
		&http.Server{Addr: ":8080", Handler: business, ReadHeaderTimeout: 5 * time.Second},
		&http.Server{Addr: ":9090", Handler: diagnostic, ReadHeaderTimeout: 5 * time.Second},
	)
}

type sealContract struct {
	BusinessStatus   string
	BusinessSealed   bool
	DiagnosticStatus string
	DiagnosticSealed bool
}

func sealContractFromEnv() (sealContract, error) {
	contract := sealContract{
		BusinessStatus:   envOrDefault("BUSINESS_STATUS", "complete"),
		DiagnosticStatus: envOrDefault("DIAGNOSTIC_STATUS", "diagnostic"),
	}
	var err error
	contract.BusinessSealed, err = strconv.ParseBool(envOrDefault("BUSINESS_SEALED", "true"))
	if err != nil {
		return sealContract{}, errors.New("BUSINESS_SEALED must be a boolean")
	}
	contract.DiagnosticSealed, err = strconv.ParseBool(envOrDefault("DIAGNOSTIC_SEALED", "false"))
	if err != nil {
		return sealContract{}, errors.New("DIAGNOSTIC_SEALED must be a boolean")
	}
	return contract, nil
}

func cursedEndpointHandlers(contract sealContract, track string, logger *log.Logger) (http.Handler, http.Handler) {
	business := http.NewServeMux()
	business.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"alive": true})
	})
	business.HandleFunc("GET /ready", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ready": true, "track": track})
	})
	business.HandleFunc("GET /seal", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, sealResponse{Status: contract.BusinessStatus, Sealed: contract.BusinessSealed})
	})

	diagnostic := http.NewServeMux()
	diagnostic.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": contract.DiagnosticStatus, "track": track})
	})
	diagnostic.HandleFunc("GET /seal", func(w http.ResponseWriter, _ *http.Request) {
		logger.Printf("diagnostic listener handled a seal request track=%s", track)
		writeJSON(w, http.StatusOK, sealResponse{Status: contract.DiagnosticStatus, Sealed: contract.DiagnosticSealed})
	})

	return business, diagnostic
}

type sealResponse struct {
	Status string `json:"status"`
	Sealed bool   `json:"sealed"`
}

func runAuditAgent(ctx context.Context, logger *log.Logger) error {
	kube, err := newKubeClientFromServiceAccount()
	if err != nil {
		return fmt.Errorf("load Kubernetes service account credentials: %w", err)
	}

	var stateMu sync.RWMutex
	state := auditAttestation{}

	server := http.NewServeMux()
	server.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"alive": true})
	})
	server.HandleFunc("GET /attestation", func(w http.ResponseWriter, _ *http.Request) {
		stateMu.RLock()
		current := state
		stateMu.RUnlock()
		writeJSON(w, http.StatusOK, current)
	})

	go func() {
		refreshAuditAttestation(ctx, kube, logger, func(next auditAttestation) {
			stateMu.Lock()
			state = next
			stateMu.Unlock()
		})
	}()

	return serveHTTP(ctx, logger, &http.Server{
		Addr:              ":8080",
		Handler:           server,
		ReadHeaderTimeout: 5 * time.Second,
	})
}

type auditAttestation struct {
	AuditLedgerReadable    bool
	AuditLedgerClean       bool
	RestrictedLedgerDenied bool
	ConfigMapListDenied    bool
	SupportSecretDenied    bool
	SecretListDenied       bool
}

func (a auditAttestation) complete() bool {
	return a.AuditLedgerReadable && a.AuditLedgerClean && a.RestrictedLedgerDenied && a.ConfigMapListDenied &&
		a.SupportSecretDenied && a.SecretListDenied
}

func refreshAuditAttestation(
	ctx context.Context,
	kube *kubeClient,
	logger *log.Logger,
	update func(auditAttestation),
) {
	refresh := func() {
		report, err := inspectAuditPermissions(ctx, kube)
		if err != nil {
			logger.Printf("audit-agent permission check is waiting: %v", err)
			update(auditAttestation{})
			return
		}
		update(report)
		logger.Printf(
			"audit-agent permission check: audit-ledger-readable=%t audit-ledger-clean=%t restricted-ledger-denied=%t configmap-list-denied=%t support-secret-denied=%t secret-list-denied=%t complete=%t",
			report.AuditLedgerReadable,
			report.AuditLedgerClean,
			report.RestrictedLedgerDenied,
			report.ConfigMapListDenied,
			report.SupportSecretDenied,
			report.SecretListDenied,
			report.complete(),
		)
	}

	refresh()
	ticker := time.NewTicker(verificationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}

func inspectAuditPermissions(ctx context.Context, kube *kubeClient) (auditAttestation, error) {
	var report auditAttestation

	configMapPath := namespacedResourcePath(kube.namespace, "configmaps", auditLedgerName)
	var configMap struct {
		Data map[string]string
	}
	status, err := kube.getJSON(ctx, configMapPath, &configMap)
	if err != nil {
		return report, fmt.Errorf("read authorized ConfigMap: %w", err)
	}
	report.AuditLedgerReadable = status == http.StatusOK && configMap.Data["record"] == "audit-only"
	report.AuditLedgerClean = stringMapIs(configMap.Data, map[string]string{"record": "audit-only"})

	report.RestrictedLedgerDenied, err = kube.isForbidden(ctx, namespacedResourcePath(kube.namespace, "configmaps", restrictedLedgerName))
	if err != nil {
		return report, fmt.Errorf("check other ConfigMap access: %w", err)
	}

	report.ConfigMapListDenied, err = kube.isForbidden(ctx, namespacedResourcePath(kube.namespace, "configmaps", ""))
	if err != nil {
		return report, fmt.Errorf("check ConfigMap list access: %w", err)
	}

	report.SupportSecretDenied, err = kube.isForbidden(ctx, namespacedResourcePath(kube.namespace, "secrets", supportSecretName))
	if err != nil {
		return report, fmt.Errorf("check support Secret access: %w", err)
	}

	report.SecretListDenied, err = kube.isForbidden(ctx, namespacedResourcePath(kube.namespace, "secrets", ""))
	if err != nil {
		return report, fmt.Errorf("check Secret list access: %w", err)
	}

	return report, nil
}

func runSupportAgent(ctx context.Context, logger *log.Logger) error {
	kube, err := newKubeClientFromServiceAccount()
	if err != nil {
		return fmt.Errorf("load Kubernetes service account credentials: %w", err)
	}

	var stateMu sync.RWMutex
	ready := false
	server := http.NewServeMux()
	server.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"alive": true})
	})
	server.HandleFunc("GET /support", func(w http.ResponseWriter, _ *http.Request) {
		stateMu.RLock()
		current := ready
		stateMu.RUnlock()
		if !current {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "waiting", "processed": false})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "processed": true})
	})

	go func() {
		refresh := func() {
			readable, err := supportSecretIsReadable(ctx, kube)
			if err != nil {
				logger.Printf("support-agent secret check is waiting: %v", err)
				readable = false
			}
			stateMu.Lock()
			ready = readable
			stateMu.Unlock()
			logger.Printf("support-agent authorized secret available=%t", readable)
		}
		refresh()
		ticker := time.NewTicker(verificationInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()

	return serveHTTP(ctx, logger, &http.Server{
		Addr:              ":8080",
		Handler:           server,
		ReadHeaderTimeout: 5 * time.Second,
	})
}

func supportSecretIsReadable(ctx context.Context, kube *kubeClient) (bool, error) {
	var secret struct {
		Data map[string]string
	}
	status, err := kube.getJSON(ctx, namespacedResourcePath(kube.namespace, "secrets", supportSecretName), &secret)
	if err != nil {
		return false, err
	}
	if status != http.StatusOK {
		return false, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(secret.Data["payload"])
	if err != nil {
		return false, nil
	}
	return string(decoded) == "fictional-support-value", nil
}

func runBackoffWatcher(ctx context.Context, stdout io.Writer, logger *log.Logger) error {
	kube, err := newKubeClientFromServiceAccount()
	if err != nil {
		return fmt.Errorf("load Kubernetes service account credentials: %w", err)
	}
	client := newWorkloadHTTPClient()
	return runWatcher(ctx, modeBackoffWatcher, stdout, logger, func() (string, error) {
		return deriveFlag("haunted-loop")
	}, loopStableDuration, func(ctx context.Context) (bool, error) {
		return verifyHauntedLoop(ctx, kube, client)
	})
}

func verifyHauntedLoop(ctx context.Context, kube *kubeClient, client *http.Client) (bool, error) {
	for _, path := range []string{"/ready", "/light"} {
		status, body, err := getHTTP(ctx, client, "http://"+hauntedLoopService+path)
		if err != nil {
			return false, fmt.Errorf("request %s through haunted loop Service: %w", path, err)
		}
		if status != http.StatusOK {
			return false, nil
		}
		if path == "/light" {
			var response struct{ Light string }
			if err := json.Unmarshal(body, &response); err != nil {
				return false, fmt.Errorf("decode light response: %w", err)
			}
			if response.Light != "lit" {
				return false, nil
			}
		}
	}

	var runtimeConfig, phaseConfig, shadowConfig configMapObject
	for name, target := range map[string]*configMapObject{
		hauntedRuntimeConfig: &runtimeConfig,
		hauntedPhasesConfig:  &phaseConfig,
		hauntedShadowConfig:  &shadowConfig,
	} {
		status, err := kube.getJSON(ctx, namespacedResourcePath(hauntedLoopNamespace, "configmaps", name), target)
		if err != nil {
			return false, fmt.Errorf("read %s ConfigMap: %w", name, err)
		}
		if status != http.StatusOK {
			return false, nil
		}
	}
	if !stringMapIs(runtimeConfig.Data, map[string]string{
		"WARMUP_SECONDS":   strconv.Itoa(hauntedWarmupSeconds),
		"LISTENER_SECONDS": strconv.Itoa(hauntedListenerSeconds),
	}) || !stringMapIs(phaseConfig.Data, map[string]string{
		"PHASE_LISTENER":    "HTTP listener active",
		"PHASE_BOOTSTRAP":   "bootstrap in progress",
		"PHASE_INITIALIZED": "application initialized",
	}) || !stringMapIs(shadowConfig.Data, map[string]string{"WARMUP_SECONDS": "61"}) {
		return false, nil
	}

	var deployment deploymentObject
	status, err := kube.getJSON(ctx, appsResourcePath(hauntedLoopNamespace, "deployments", hauntedLoopService), &deployment)
	if err != nil {
		return false, fmt.Errorf("read haunted loop Deployment: %w", err)
	}
	if status != http.StatusOK || !deploymentIsCurrent(deployment) {
		return false, nil
	}
	var watcherDeployment deploymentObject
	status, err = kube.getJSON(ctx, appsResourcePath(hauntedLoopNamespace, "deployments", modeBackoffWatcher), &watcherDeployment)
	if err != nil {
		return false, fmt.Errorf("read backoff watcher Deployment: %w", err)
	}
	if status != http.StatusOK || !deploymentIsCurrent(watcherDeployment) {
		return false, nil
	}
	appContainer, appOK := namedContainer(deployment, hauntedLoopContainerName)
	watcherContainer, watcherOK := namedContainer(watcherDeployment, modeBackoffWatcher)
	if !appOK || !watcherOK || appContainer.Image == "" || appContainer.Image != watcherContainer.Image ||
		!equalStrings(appContainer.Args, []string{modeHauntedLoop}) ||
		!hauntedDeploymentConfigurationIsSafe(deployment, appContainer, map[string]map[string]string{
			hauntedRuntimeConfig: runtimeConfig.Data,
			hauntedPhasesConfig:  phaseConfig.Data,
			hauntedShadowConfig:  shadowConfig.Data,
		}) {
		return false, nil
	}
	var service serviceObject
	status, err = kube.getJSON(ctx, namespacedResourcePath(hauntedLoopNamespace, "services", hauntedLoopService), &service)
	if err != nil {
		return false, fmt.Errorf("read haunted loop Service: %w", err)
	}
	if status != http.StatusOK || !serviceIsValid(service, map[string]string{"app": hauntedLoopService}) ||
		!servicePortTargets(service, appContainer.Ports, 80, 8080) {
		return false, nil
	}
	pods, err := listPodsForSelector(ctx, kube, hauntedLoopNamespace, selectorString(service.Spec.Selector))
	if err != nil {
		return false, fmt.Errorf("list haunted loop Service Pods: %w", err)
	}
	if len(pods) == 0 {
		return false, nil
	}
	for _, pod := range pods {
		if pod.Status.Phase != "Running" || pod.Status.PodIP == "" || !podReady(pod) ||
			!containerStatusIsReady(pod.Status.ContainerStatuses, hauntedLoopContainerName, true) ||
			!containerStatusIsReady(pod.Status.InitContainerStatuses, "ghost-sentinel", true) {
			return false, nil
		}
	}
	return true, nil
}

func hauntedDeploymentConfigurationIsSafe(
	deployment deploymentObject,
	app containerObject,
	configMaps map[string]map[string]string,
) bool {
	podSpec := deployment.Spec.Template.Spec
	if len(podSpec.Containers) != 1 || len(podSpec.InitContainers) != 1 || len(podSpec.ReadinessGates) != 0 {
		return false
	}
	warmupSeconds, ok := hauntedWarmupFromConfigMaps(app, configMaps)
	if !ok || containerOverridesConfig(app, map[string]bool{
		"WARMUP_SECONDS": true, "LISTENER_SECONDS": true, "PHASE_LISTENER": true,
		"PHASE_BOOTSTRAP": true, "PHASE_INITIALIZED": true,
	}) || !containerHasPort(app.Ports, "http", 8080) || !hauntedProbesAreSafe(app, warmupSeconds) {
		return false
	}

	sidecar := podSpec.InitContainers[0]
	if sidecar.Name != "ghost-sentinel" || sidecar.Image != "registry.k8s.io/pause:3.10" ||
		sidecar.RestartPolicy != "Always" || len(sidecar.Ports) != 0 ||
		!(probeTargets(sidecar.ReadinessProbe, sidecar, "/ready") ||
			probeTargets(sidecar.ReadinessProbe, sidecar, "/light")) ||
		!probePortIs(sidecar.ReadinessProbe.HTTPGet.Port, nil, 8080) {
		return false
	}

	minimumProgress := int32(warmupSeconds) + deployment.Spec.MinReadySeconds + 10
	progressDeadline := int32(600)
	if deployment.Spec.ProgressDeadlineSeconds != nil {
		progressDeadline = *deployment.Spec.ProgressDeadlineSeconds
	}
	return progressDeadline >= minimumProgress
}

func hauntedWarmupFromConfigMaps(container containerObject, configMaps map[string]map[string]string) (int, bool) {
	required := map[string]bool{
		hauntedRuntimeConfig: true,
		hauntedPhasesConfig:  true,
	}
	allowed := map[string]bool{
		hauntedRuntimeConfig: true,
		hauntedPhasesConfig:  true,
		hauntedShadowConfig:  true,
	}
	seen := make(map[string]bool, len(configMaps))
	if len(container.EnvFrom) < len(required) || len(container.EnvFrom) > len(allowed) {
		return 0, false
	}

	warmup := ""
	for _, source := range container.EnvFrom {
		name := source.ConfigMapRef.Name
		if name == "" || source.SecretRef.Name != "" || source.Prefix != "" || !allowed[name] || seen[name] {
			return 0, false
		}
		seen[name] = true
		delete(required, name)
		data, ok := configMaps[name]
		if !ok {
			return 0, false
		}
		if value, ok := data["WARMUP_SECONDS"]; ok {
			warmup = value
		}
	}
	if len(required) != 0 {
		return 0, false
	}

	seconds, err := strconv.Atoi(warmup)
	if err != nil || seconds < 1 || seconds > 120 {
		return 0, false
	}
	return seconds, true
}

func containerHasPort(ports []containerPort, name string, number int) bool {
	for _, port := range ports {
		if port.Name == name && port.ContainerPort == number {
			return true
		}
	}
	return false
}

func hauntedProbesAreSafe(container containerObject, warmupSeconds int) bool {
	minimumBudget := time.Duration(warmupSeconds)*time.Second + loopStartupMargin
	if !(probeTargets(container.StartupProbe, container, "/ready") ||
		probeTargets(container.StartupProbe, container, "/light")) ||
		probeBudget(container.StartupProbe) < minimumBudget ||
		!(probeTargets(container.ReadinessProbe, container, "/ready") ||
			probeTargets(container.ReadinessProbe, container, "/light")) {
		return false
	}
	return probeTargets(container.LivenessProbe, container, "/ready") ||
		probeTargets(container.LivenessProbe, container, "/healthz") ||
		probeTargets(container.LivenessProbe, container, "/process-live")
}

type configMapObject struct {
	Data map[string]string `json:"data"`
}

type deploymentObject struct {
	Metadata struct {
		Generation int64 `json:"generation"`
	} `json:"metadata"`
	Spec struct {
		Replicas                *int32 `json:"replicas"`
		MinReadySeconds         int32  `json:"minReadySeconds"`
		ProgressDeadlineSeconds *int32 `json:"progressDeadlineSeconds"`
		Template                struct {
			Metadata struct {
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec podSpecObject `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration  int64 `json:"observedGeneration"`
		Replicas            int32 `json:"replicas"`
		UpdatedReplicas     int32 `json:"updatedReplicas"`
		ReadyReplicas       int32 `json:"readyReplicas"`
		AvailableReplicas   int32 `json:"availableReplicas"`
		UnavailableReplicas int32 `json:"unavailableReplicas"`
	} `json:"status"`
}

type podSpecObject struct {
	ServiceAccountName           string            `json:"serviceAccountName"`
	AutomountServiceAccountToken *bool             `json:"automountServiceAccountToken"`
	Containers                   []containerObject `json:"containers"`
	InitContainers               []containerObject `json:"initContainers"`
	Volumes                      []volumeObject    `json:"volumes"`
	ReadinessGates               []readinessGate   `json:"readinessGates"`
}

type readinessGate struct {
	ConditionType string `json:"conditionType"`
}

type containerObject struct {
	Name           string          `json:"name"`
	Image          string          `json:"image"`
	Command        []string        `json:"command"`
	Args           []string        `json:"args"`
	Env            []envVarObject  `json:"env"`
	EnvFrom        []envFromObject `json:"envFrom"`
	Ports          []containerPort `json:"ports"`
	VolumeMounts   []volumeMount   `json:"volumeMounts"`
	RestartPolicy  string          `json:"restartPolicy"`
	LivenessProbe  *probeObject    `json:"livenessProbe"`
	ReadinessProbe *probeObject    `json:"readinessProbe"`
	StartupProbe   *probeObject    `json:"startupProbe"`
}

type envVarObject struct {
	Name      string          `json:"name"`
	Value     string          `json:"value"`
	ValueFrom *envValueSource `json:"valueFrom"`
}

type envValueSource struct {
	FieldRef         *struct{}           `json:"fieldRef"`
	ResourceFieldRef *struct{}           `json:"resourceFieldRef"`
	ConfigMapKeyRef  *struct{}           `json:"configMapKeyRef"`
	SecretKeyRef     *secretKeyReference `json:"secretKeyRef"`
}

type envFromObject struct {
	Prefix       string `json:"prefix"`
	ConfigMapRef struct {
		Name string `json:"name"`
	} `json:"configMapRef"`
	SecretRef struct {
		Name string `json:"name"`
	} `json:"secretRef"`
}

type secretKeyReference struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type volumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
}

type volumeObject struct {
	Secret    *secretVolume    `json:"secret"`
	Projected *projectedVolume `json:"projected"`
}

type secretVolume struct {
	SecretName string `json:"secretName"`
}

type projectedVolume struct {
	Sources []projectedVolumeSource `json:"sources"`
}

type projectedVolumeSource struct {
	Secret *secretVolume `json:"secret"`
}

func namedContainer(deployment deploymentObject, name string) (containerObject, bool) {
	for _, container := range deployment.Spec.Template.Spec.Containers {
		if container.Name == name {
			return container, true
		}
	}
	return containerObject{}, false
}

func containerLoadsConfigMaps(container containerObject, names ...string) bool {
	if len(container.EnvFrom) != len(names) {
		return false
	}
	for i, name := range names {
		if container.EnvFrom[i].ConfigMapRef.Name != name {
			return false
		}
	}
	return true
}

func containerOverridesConfig(container containerObject, controlled map[string]bool) bool {
	for _, variable := range container.Env {
		if controlled[variable.Name] {
			return true
		}
	}
	return false
}

func stringMapIs(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for key, value := range want {
		if got[key] != value {
			return false
		}
	}
	return true
}

func containerEnvIs(container containerObject, name, value string) bool {
	matches := 0
	for _, variable := range container.Env {
		if variable.Name != name {
			continue
		}
		matches++
		if variable.Value != value || variable.ValueFrom != nil {
			return false
		}
	}
	return matches == 1
}

func cursedBackendConfigIsValid(container containerObject, track string) bool {
	return containerLoadsConfigMaps(container, cursedContractConfig) && len(container.Env) == 1 &&
		!containerOverridesConfig(container, map[string]bool{
			"BUSINESS_STATUS": true, "BUSINESS_SEALED": true,
			"DIAGNOSTIC_STATUS": true, "DIAGNOSTIC_SEALED": true, "CONTRACT_STATUS": true,
		}) && containerEnvIs(container, "BACKEND_TRACK", track)
}

type containerPort struct {
	Name          string `json:"name"`
	ContainerPort int    `json:"containerPort"`
}

type probeObject struct {
	HTTPGet             *httpGetProbe `json:"httpGet"`
	InitialDelaySeconds int           `json:"initialDelaySeconds"`
	PeriodSeconds       int           `json:"periodSeconds"`
	FailureThreshold    int           `json:"failureThreshold"`
}

type httpGetProbe struct {
	Path   string          `json:"path"`
	Port   json.RawMessage `json:"port"`
	Host   string          `json:"host"`
	Scheme string          `json:"scheme"`
}

func deploymentIsCurrent(deployment deploymentObject) bool {
	desiredReplicas := int32(1)
	if deployment.Spec.Replicas != nil {
		desiredReplicas = *deployment.Spec.Replicas
	}
	if desiredReplicas < 1 {
		return false
	}

	status := deployment.Status
	return status.ObservedGeneration >= deployment.Metadata.Generation &&
		status.Replicas == desiredReplicas &&
		status.UpdatedReplicas == desiredReplicas &&
		status.ReadyReplicas == desiredReplicas &&
		status.AvailableReplicas == desiredReplicas &&
		status.UnavailableReplicas == 0
}

func probeTargets(probe *probeObject, container containerObject, path string) bool {
	if probe == nil || probe.HTTPGet == nil || probe.HTTPGet.Path != path {
		return false
	}
	if probe.HTTPGet.Host != "" || (probe.HTTPGet.Scheme != "" && probe.HTTPGet.Scheme != "HTTP") {
		return false
	}
	return probePortIs(probe.HTTPGet.Port, container.Ports, 8080)
}

func probePortIs(rawPort json.RawMessage, ports []containerPort, expected int) bool {
	var number int
	if err := json.Unmarshal(rawPort, &number); err == nil {
		return number == expected
	}

	var name string
	if err := json.Unmarshal(rawPort, &name); err != nil || name == "" {
		return false
	}
	for _, port := range ports {
		if port.Name == name {
			return port.ContainerPort == expected
		}
	}
	return false
}

func probeBudget(probe *probeObject) time.Duration {
	if probe == nil {
		return 0
	}
	period := probe.PeriodSeconds
	if period == 0 {
		period = 10
	}
	failureThreshold := probe.FailureThreshold
	if failureThreshold == 0 {
		failureThreshold = 3
	}
	return time.Duration(probe.InitialDelaySeconds+period*failureThreshold) * time.Second
}

type serviceObject struct {
	Spec serviceSpec `json:"spec"`
}

type serviceSpec struct {
	Type                     string            `json:"type"`
	ClusterIP                string            `json:"clusterIP"`
	Selector                 map[string]string `json:"selector"`
	Ports                    []servicePort     `json:"ports"`
	PublishNotReadyAddresses bool              `json:"publishNotReadyAddresses"`
}

type servicePort struct {
	Port       int             `json:"port"`
	TargetPort json.RawMessage `json:"targetPort"`
}

type podList struct {
	Items []podObject
}

type podObject struct {
	Metadata struct {
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec   podSpecObject `json:"spec"`
	Status struct {
		Phase                 string            `json:"phase"`
		PodIP                 string            `json:"podIP"`
		Conditions            []podCondition    `json:"conditions"`
		ContainerStatuses     []containerStatus `json:"containerStatuses"`
		InitContainerStatuses []containerStatus `json:"initContainerStatuses"`
	} `json:"status"`
}

type podCondition struct {
	Type   string `json:"type"`
	Status string `json:"status"`
}

type containerStatus struct {
	Name         string `json:"name"`
	Ready        bool   `json:"ready"`
	RestartCount int32  `json:"restartCount"`
}

func verifyCursedEndpoints(ctx context.Context, kube *kubeClient, client *http.Client) (bool, error) {
	var contractMap configMapObject
	status, err := kube.getJSON(ctx, namespacedResourcePath(cursedEndpointsNamespace, "configmaps", cursedContractConfig), &contractMap)
	if err != nil {
		return false, fmt.Errorf("read seal contract: %w", err)
	}
	if status != http.StatusOK || !stringMapIs(contractMap.Data, map[string]string{
		"BUSINESS_STATUS":   "complete",
		"BUSINESS_SEALED":   "true",
		"DIAGNOSTIC_STATUS": "diagnostic",
		"DIAGNOSTIC_SEALED": "false",
	}) {
		return false, nil
	}

	var referenceImage string
	backendDeployments := make(map[string]deploymentObject, 2)
	for _, name := range []string{cursedStableDeployment, cursedCanaryDeployment, modeEndpointWatcher} {
		var deployment deploymentObject
		status, err := kube.getJSON(ctx, appsResourcePath(cursedEndpointsNamespace, "deployments", name), &deployment)
		if err != nil {
			return false, fmt.Errorf("read backend Deployment %s: %w", name, err)
		}
		if status != http.StatusOK || !deploymentIsCurrent(deployment) {
			return false, nil
		}
		containerName := "backend"
		wantArgs := []string{modeCursedEndpoints}
		if name == modeEndpointWatcher {
			containerName = modeEndpointWatcher
			wantArgs = []string{modeEndpointWatcher}
		}
		container, ok := namedContainer(deployment, containerName)
		if !ok || container.Image == "" || !equalStrings(container.Args, wantArgs) {
			return false, nil
		}
		if name != modeEndpointWatcher {
			track := strings.TrimPrefix(name, "spectral-")
			if !cursedBackendDeploymentIsValid(deployment, container, track) {
				return false, nil
			}
			backendDeployments[track] = deployment
		}
		if referenceImage == "" {
			referenceImage = container.Image
		} else if container.Image != referenceImage {
			return false, nil
		}
	}

	for _, check := range []struct {
		name     string
		selector map[string]string
		track    string
	}{
		{name: cursedEndpointsService, selector: map[string]string{"app": "spectral-backend"}},
		{name: cursedStableService, selector: map[string]string{"app": "spectral-backend", "track": "stable"}, track: "stable"},
		{name: cursedCanaryService, selector: map[string]string{"app": "spectral-backend", "track": "canary"}, track: "canary"},
	} {
		var service serviceObject
		status, err = kube.getJSON(ctx, namespacedResourcePath(cursedEndpointsNamespace, "services", check.name), &service)
		if err != nil {
			return false, fmt.Errorf("read %s Service: %w", check.name, err)
		}
		if status != http.StatusOK || !serviceIsValid(service, check.selector) {
			return false, nil
		}

		pods, err := listPodsForSelector(ctx, kube, cursedEndpointsNamespace, selectorString(service.Spec.Selector))
		if err != nil {
			return false, fmt.Errorf("list %s Service Pods: %w", check.name, err)
		}
		if len(pods) == 0 {
			return false, nil
		}
		tracks := make(map[string]int, 2)
		for _, pod := range pods {
			track := pod.Metadata.Labels["track"]
			if (check.track != "" && track != check.track) ||
				(track != "stable" && track != "canary") ||
				pod.Status.Phase != "Running" || pod.Status.PodIP == "" || !podReady(pod) ||
				!containerStatusIsReady(pod.Status.ContainerStatuses, "backend", false) {
				return false, nil
			}
			tracks[track]++
			backend, ok := namedContainer(backendDeployments[track], "backend")
			if !ok || !containerPortsAreValid(backend.Ports) ||
				!servicePortTargets(service, backend.Ports, 80, 8080) ||
				!businessSealAt(ctx, client, net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(8080))) {
				return false, nil
			}
		}
		if (check.track == "" && (tracks["stable"] == 0 || tracks["canary"] == 0)) ||
			(check.track != "" && tracks[check.track] == 0) {
			return false, nil
		}
		if !businessSealAt(ctx, client, check.name+":80") {
			return false, nil
		}
	}
	return true, nil
}

func cursedBackendDeploymentIsValid(deployment deploymentObject, container containerObject, track string) bool {
	return len(deployment.Spec.Template.Spec.ReadinessGates) == 0 &&
		stringMapIs(deployment.Spec.Template.Metadata.Labels, map[string]string{
			"app": "spectral-backend", "track": track,
		}) && cursedBackendConfigIsValid(container, track) &&
		containerPortsAreValid(container.Ports) &&
		probeTargets(container.ReadinessProbe, container, "/ready")
}

func containerPortsAreValid(ports []containerPort) bool {
	return len(ports) == 2 && namedPortIs(ports, "web", 8080) && namedPortIs(ports, "admin", 9090)
}

func namedPortIs(ports []containerPort, name string, number int) bool {
	for _, port := range ports {
		if port.Name == name && port.ContainerPort == number {
			return true
		}
	}
	return false
}

func selectorString(selector map[string]string) string {
	parts := make([]string, 0, len(selector))
	for key, value := range selector {
		parts = append(parts, key+"="+value)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func serviceIsValid(service serviceObject, selector map[string]string) bool {
	return service.Spec.Type == "ClusterIP" && service.Spec.ClusterIP != "" &&
		service.Spec.ClusterIP != "None" && stringMapIs(service.Spec.Selector, selector) &&
		len(service.Spec.Ports) == 1 && service.Spec.Ports[0].Port == 80 &&
		!service.Spec.PublishNotReadyAddresses
}

func servicePortTargets(service serviceObject, ports []containerPort, servicePort, targetPort int) bool {
	if len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != servicePort {
		return false
	}
	resolved, ok := resolveTargetPort(service.Spec.Ports[0].TargetPort, []containerObject{{Ports: ports}})
	return ok && resolved == targetPort
}

func listPodsForSelector(ctx context.Context, kube *kubeClient, namespace, selector string) ([]podObject, error) {
	var pods podList
	path := namespacedResourcePath(namespace, "pods", "") + "?labelSelector=" + url.QueryEscape(selector)
	status, err := kube.getJSON(ctx, path, &pods)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list Pods returned HTTP %d", status)
	}
	return pods.Items, nil
}

func podReady(pod podObject) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == "Ready" && condition.Status == "True" {
			return true
		}
	}
	return false
}

func containerStatusIsReady(statuses []containerStatus, name string, noRestarts bool) bool {
	for _, status := range statuses {
		if status.Name != name {
			continue
		}
		return status.Ready && (!noRestarts || status.RestartCount == 0)
	}
	return false
}

func resolveTargetPort(raw json.RawMessage, containers []containerObject) (int, bool) {
	var number int
	if err := json.Unmarshal(raw, &number); err == nil && number > 0 {
		return number, true
	}
	var name string
	if err := json.Unmarshal(raw, &name); err != nil || name == "" {
		return 0, false
	}
	for _, container := range containers {
		for _, port := range container.Ports {
			if port.Name == name && port.ContainerPort > 0 {
				return port.ContainerPort, true
			}
		}
	}
	return 0, false
}

func businessSealAt(ctx context.Context, client *http.Client, address string) bool {
	status, body, err := getHTTP(ctx, client, "http://"+address+"/seal")
	if err != nil || status != http.StatusOK {
		return false
	}
	var response sealResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return false
	}
	return response.Status == "complete" && response.Sealed
}

func runEndpointWatcher(ctx context.Context, stdout io.Writer, logger *log.Logger) error {
	kube, err := newKubeClientFromServiceAccount()
	if err != nil {
		return fmt.Errorf("load Kubernetes service account credentials: %w", err)
	}
	client := newWorkloadHTTPClient()
	return runWatcher(ctx, modeEndpointWatcher, stdout, logger, func() (string, error) {
		return deriveFlag("cursed-endpoints")
	}, 0, func(ctx context.Context) (bool, error) {
		return verifyCursedEndpoints(ctx, kube, client)
	})
}

func runPossessionAuditor(ctx context.Context, stdout io.Writer, logger *log.Logger) error {
	kube, err := newKubeClientFromServiceAccount()
	if err != nil {
		return fmt.Errorf("load Kubernetes service account credentials: %w", err)
	}
	client := newWorkloadHTTPClient()
	return runWatcher(ctx, modePossessionAuditor, stdout, logger, func() (string, error) {
		return deriveFlag("possessed-sa")
	}, 0, func(ctx context.Context) (bool, error) {
		return verifyPossessedAccount(ctx, kube, client)
	})
}

func verifyPossessedAccount(ctx context.Context, kube *kubeClient, client *http.Client) (bool, error) {
	appImages := make(map[string]string, 2)
	deployments := make(map[string]deploymentObject, 2)
	for name, expectedSA := range map[string]string{auditAgentName: auditAgentName, supportAgentName: supportAgentName} {
		var deployment deploymentObject
		status, err := kube.getJSON(ctx, appsResourcePath(possessedAccountNamespace, "deployments", name), &deployment)
		if err != nil {
			return false, fmt.Errorf("read %s Deployment: %w", name, err)
		}
		if status != http.StatusOK || !deploymentIsCurrent(deployment) ||
			deployment.Spec.Template.Spec.ServiceAccountName != expectedSA {
			return false, nil
		}
		container, ok := namedContainer(deployment, name)
		wantMode := name
		if !ok || container.Image == "" || !equalStrings(container.Args, []string{wantMode}) {
			return false, nil
		}
		if !podHasNoSecretInjection(deployment.Spec.Template.Spec, container) {
			return false, nil
		}
		if deployment.Spec.Template.Spec.AutomountServiceAccountToken != nil &&
			!*deployment.Spec.Template.Spec.AutomountServiceAccountToken {
			return false, nil
		}
		appImages[name] = container.Image
		deployments[name] = deployment
	}
	var auditLedger configMapObject
	status, err := kube.getJSON(ctx, namespacedResourcePath(possessedAccountNamespace, "configmaps", auditLedgerName), &auditLedger)
	if err != nil {
		return false, fmt.Errorf("read audit ledger: %w", err)
	}
	if status != http.StatusOK || !stringMapIs(auditLedger.Data, map[string]string{"record": "audit-only"}) {
		return false, nil
	}
	var observerDeployment deploymentObject
	status, err = kube.getJSON(ctx, appsResourcePath(possessedAccountNamespace, "deployments", possessionObserverName), &observerDeployment)
	if err != nil {
		return false, fmt.Errorf("read possession observer Deployment: %w", err)
	}
	if status != http.StatusOK || !deploymentIsCurrent(observerDeployment) {
		return false, nil
	}
	observerContainer, ok := namedContainer(observerDeployment, possessionObserverName)
	if !ok || observerContainer.Image == "" || !equalStrings(observerContainer.Args, []string{modePossessionAuditor}) ||
		appImages[auditAgentName] != observerContainer.Image || appImages[supportAgentName] != observerContainer.Image {
		return false, nil
	}

	auditPod, ok, err := findReadyPod(ctx, kube, possessedAccountNamespace, "app="+auditAgentName)
	if err != nil || !ok {
		if err != nil {
			return false, fmt.Errorf("find audit-agent Pod: %w", err)
		}
		return false, nil
	}
	status, body, err := getHTTP(ctx, client, "http://"+net.JoinHostPort(auditPod.Status.PodIP, "8080")+"/attestation")
	if err != nil {
		return false, fmt.Errorf("request audit-agent attestation: %w", err)
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("audit-agent attestation returned HTTP %d", status)
	}
	var attestation auditAttestation
	if err := json.Unmarshal(body, &attestation); err != nil {
		return false, fmt.Errorf("decode audit-agent attestation: %w", err)
	}
	if !attestation.complete() {
		return false, nil
	}

	status, body, err = getHTTP(ctx, client, "http://"+supportAgentService+":80/support")
	if err != nil {
		return false, fmt.Errorf("request support-agent Service: %w", err)
	}
	if status != http.StatusOK {
		return false, nil
	}
	var support struct {
		Status    string
		Processed bool
	}
	if err := json.Unmarshal(body, &support); err != nil {
		return false, fmt.Errorf("decode support-agent response: %w", err)
	}
	if support.Status != "ready" || !support.Processed {
		return false, nil
	}

	var supportService serviceObject
	status, err = kube.getJSON(ctx, namespacedResourcePath(possessedAccountNamespace, "services", supportAgentService), &supportService)
	if err != nil {
		return false, fmt.Errorf("read support-agent Service: %w", err)
	}
	supportContainer, ok := namedContainer(deployments[supportAgentName], supportAgentName)
	if status != http.StatusOK || !ok ||
		!serviceIsValid(supportService, map[string]string{"app": supportAgentName}) ||
		!servicePortTargets(supportService, supportContainer.Ports, 80, 8080) {
		return false, nil
	}
	return auditServiceAccountPolicies(ctx, kube)
}

func podHasNoSecretInjection(podSpec podSpecObject, container containerObject) bool {
	return len(podSpec.Containers) == 1 && len(podSpec.InitContainers) == 0 && len(podSpec.Volumes) == 0 &&
		len(container.Env) == 0 && len(container.EnvFrom) == 0 && len(container.VolumeMounts) == 0
}

func findReadyPod(ctx context.Context, kube *kubeClient, namespace, selector string) (podObject, bool, error) {
	var pods podList
	path := namespacedResourcePath(namespace, "pods", "") + "?labelSelector=" + url.QueryEscape(selector)
	status, err := kube.getJSON(ctx, path, &pods)
	if err != nil {
		return podObject{}, false, err
	}
	if status != http.StatusOK {
		return podObject{}, false, fmt.Errorf("list Pods returned HTTP %d", status)
	}
	for _, pod := range pods.Items {
		if pod.Status.Phase == "Running" && pod.Status.PodIP != "" && podReady(pod) {
			return pod, true, nil
		}
	}
	return podObject{}, false, nil
}

type roleList struct {
	Items []roleObject `json:"items"`
}

type roleObject struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Rules []policyRule `json:"rules"`
}

type policyRule struct {
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	Verbs           []string `json:"verbs"`
	ResourceNames   []string `json:"resourceNames"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

type roleBindingList struct {
	Items []roleBindingObject `json:"items"`
}

type roleBindingObject struct {
	Subjects []roleSubject `json:"subjects"`
	RoleRef  struct {
		APIGroup string `json:"apiGroup"`
		Kind     string `json:"kind"`
		Name     string `json:"name"`
	} `json:"roleRef"`
}

type roleSubject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

func auditServiceAccountPolicies(ctx context.Context, kube *kubeClient) (bool, error) {
	var roles roleList
	status, err := kube.getJSON(ctx, rbacResourcePath(possessedAccountNamespace, "roles"), &roles)
	if err != nil {
		return false, fmt.Errorf("list namespaced Roles: %w", err)
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("list namespaced Roles returned HTTP %d", status)
	}

	var bindings roleBindingList
	status, err = kube.getJSON(ctx, rbacResourcePath(possessedAccountNamespace, "rolebindings"), &bindings)
	if err != nil {
		return false, fmt.Errorf("list namespaced RoleBindings: %w", err)
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("list namespaced RoleBindings returned HTTP %d", status)
	}

	rolesByName := make(map[string]roleObject, len(roles.Items))
	for _, role := range roles.Items {
		rolesByName[role.Metadata.Name] = role
	}

	for _, identity := range []struct {
		name     string
		resource string
		object   string
	}{
		{name: auditAgentName, resource: "configmaps", object: auditLedgerName},
		{name: supportAgentName, resource: "secrets", object: supportSecretName},
	} {
		matchedBindings := 0
		for _, binding := range bindings.Items {
			matches, broadSubject := bindingSubjects(possessedAccountNamespace, identity.name, binding.Subjects)
			if !matches {
				continue
			}
			if broadSubject || !bindingHasOnlyServiceAccount(binding, identity.name) ||
				binding.RoleRef.APIGroup != "rbac.authorization.k8s.io" || binding.RoleRef.Kind != "Role" {
				return false, nil
			}
			role, ok := rolesByName[binding.RoleRef.Name]
			if !ok || !roleHasOnlyNamedRead(role.Rules, identity.resource, identity.object) {
				return false, nil
			}
			matchedBindings++
		}
		if matchedBindings != 1 {
			return false, nil
		}
	}
	return true, nil
}

func bindingSubjects(namespace, serviceAccount string, subjects []roleSubject) (matches bool, broad bool) {
	username := "system:serviceaccount:" + namespace + ":" + serviceAccount
	for _, subject := range subjects {
		switch subject.Kind {
		case "ServiceAccount":
			subjectNamespace := subject.Namespace
			if subjectNamespace == "" {
				subjectNamespace = namespace
			}
			if subject.Name == serviceAccount && subjectNamespace == namespace {
				matches = true
			}
		case "User":
			if subject.Name == username {
				matches = true
			}
		case "Group":
			if subject.Name == "system:serviceaccounts" ||
				subject.Name == "system:serviceaccounts:"+namespace ||
				subject.Name == "system:authenticated" {
				matches = true
				broad = true
			}
		}
	}
	return matches, broad
}

func bindingHasOnlyServiceAccount(binding roleBindingObject, name string) bool {
	if len(binding.Subjects) != 1 {
		return false
	}
	subject := binding.Subjects[0]
	return subject.Kind == "ServiceAccount" && subject.Name == name &&
		(subject.Namespace == "" || subject.Namespace == possessedAccountNamespace)
}

func roleHasOnlyNamedRead(rules []policyRule, resource, name string) bool {
	if len(rules) != 1 {
		return false
	}
	rule := rules[0]
	return equalStrings(rule.APIGroups, []string{""}) &&
		equalStrings(rule.Resources, []string{resource}) &&
		equalStrings(rule.Verbs, []string{"get"}) &&
		equalStrings(rule.ResourceNames, []string{name}) &&
		len(rule.NonResourceURLs) == 0
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func runWatcher(
	ctx context.Context,
	name string,
	stdout io.Writer,
	logger *log.Logger,
	flagForChallenge func() (string, error),
	stablePeriod time.Duration,
	verify func(context.Context) (bool, error),
) error {
	if flagForChallenge == nil {
		return fmt.Errorf("%s flag derivation is unavailable", name)
	}

	health := &http.Server{
		Addr:              ":8081",
		Handler:           healthHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		if err := health.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	shutdown := func() error {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return health.Shutdown(shutdownCtx)
	}

	ticker := time.NewTicker(verificationInterval)
	defer ticker.Stop()
	consecutiveSuccesses := 0
	stableSince := time.Time{}
	complete := false
	waitingLogged := false

	for {
		if !complete {
			ok, err := verify(ctx)
			if err != nil {
				consecutiveSuccesses = 0
				stableSince = time.Time{}
				if !waitingLogged {
					logger.Printf("%s verification is waiting: %v", name, err)
					waitingLogged = true
				}
			} else if ok {
				if consecutiveSuccesses == 0 {
					stableSince = time.Now()
				}
				consecutiveSuccesses++
				if waitingLogged {
					logger.Printf("%s verification conditions are met; confirming stability", name)
					waitingLogged = false
				}
				stableLongEnough := stablePeriod <= 0 || time.Since(stableSince) >= stablePeriod
				if consecutiveSuccesses >= verificationSuccessesRequired && stableLongEnough && ctx.Err() == nil {
					flag, err := flagForChallenge()
					if err != nil {
						_ = shutdown()
						return fmt.Errorf("derive %s flag: %w", name, err)
					}
					if _, err := fmt.Fprintln(stdout, flag); err != nil {
						_ = shutdown()
						return fmt.Errorf("write %s flag: %w", name, err)
					}
					complete = true
					logger.Printf("%s verification completed", name)
				}
			} else {
				consecutiveSuccesses = 0
				stableSince = time.Time{}
				if !waitingLogged {
					logger.Printf("%s verification conditions are not satisfied", name)
					waitingLogged = true
				}
			}
		}

		select {
		case <-ctx.Done():
			return shutdown()
		case err := <-serveErr:
			_ = shutdown()
			return fmt.Errorf("serve %s health endpoint: %w", name, err)
		case <-ticker.C:
		}
	}
}

func healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"alive": true})
	})
	return mux
}

func serveHTTP(ctx context.Context, logger *log.Logger, servers ...*http.Server) error {
	serveErr := make(chan error, len(servers))
	for _, server := range servers {
		go func(server *http.Server) {
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serveErr <- fmt.Errorf("listen on %s: %w", server.Addr, err)
			}
		}(server)
	}

	var result error
	select {
	case <-ctx.Done():
	case result = <-serveErr:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Printf("shutdown %s: %v", server.Addr, err)
			if result == nil {
				result = fmt.Errorf("shutdown %s: %w", server.Addr, err)
			}
		}
	}
	return result
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}

func readinessStatus(ready bool) int {
	if !ready {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}

func newWorkloadHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
		},
	}
}

func getHTTP(ctx context.Context, client *http.Client, rawURL string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("create HTTP request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read HTTP response: %w", err)
	}
	return resp.StatusCode, body, nil
}

type kubeClient struct {
	baseURL   string
	namespace string
	token     string
	tokenPath string
	client    *http.Client
}

func newKubeClientFromServiceAccount() (*kubeClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if host == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST is unset")
	}
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if port == "" {
		port = "443"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("invalid KUBERNETES_SERVICE_PORT %q: %w", port, err)
	}

	tokenBytes, err := os.ReadFile(serviceAccountDirectory + "/token")
	if err != nil {
		return nil, fmt.Errorf("read service account token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return nil, errors.New("service account token is empty")
	}

	caBytes, err := os.ReadFile(serviceAccountDirectory + "/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("read service account CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("service account CA contains no certificates")
	}

	namespaceBytes, err := os.ReadFile(serviceAccountDirectory + "/namespace")
	if err != nil {
		return nil, fmt.Errorf("read service account namespace: %w", err)
	}
	namespace := strings.TrimSpace(string(namespaceBytes))
	if namespace == "" {
		return nil, errors.New("service account namespace is empty")
	}

	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
	}
	return &kubeClient{
		baseURL:   "https://" + net.JoinHostPort(host, port),
		namespace: namespace,
		token:     token,
		tokenPath: serviceAccountDirectory + "/token",
		client: &http.Client{
			Transport: transport,
			Timeout:   4 * time.Second,
		},
	}, nil
}

func (c *kubeClient) getJSON(ctx context.Context, path string, dst any) (int, error) {
	resp, err := c.request(ctx, path)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(dst); err != nil {
		return resp.StatusCode, fmt.Errorf("decode Kubernetes API response: %w", err)
	}
	return resp.StatusCode, nil
}

func (c *kubeClient) isForbidden(ctx context.Context, path string) (bool, error) {
	resp, err := c.request(ctx, path)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return false, nil
	}

	var status struct {
		Kind   string `json:"kind"`
		Status string `json:"status"`
		Reason string `json:"reason"`
		Code   int    `json:"code"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&status); err != nil {
		return false, fmt.Errorf("decode Kubernetes Forbidden status: %w", err)
	}
	return status.Kind == "Status" && status.Status == "Failure" &&
		status.Reason == "Forbidden" && status.Code == http.StatusForbidden, nil
}

func (c *kubeClient) request(ctx context.Context, path string) (*http.Response, error) {
	token := c.token
	if c.tokenPath != "" {
		tokenBytes, err := os.ReadFile(c.tokenPath)
		if err != nil {
			return nil, fmt.Errorf("read service account token: %w", err)
		}
		token = strings.TrimSpace(string(tokenBytes))
	}
	if token == "" {
		return nil, errors.New("service account token is empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes API request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request Kubernetes API: %w", err)
	}
	return resp, nil
}

func namespacedResourcePath(namespace, resource, name string) string {
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/" + resource
	if name != "" {
		path += "/" + url.PathEscape(name)
	}
	return path
}

func appsResourcePath(namespace, resource, name string) string {
	return "/apis/apps/v1/namespaces/" + url.PathEscape(namespace) + "/" + resource + "/" + url.PathEscape(name)
}

func rbacResourcePath(namespace, resource string) string {
	return "/apis/rbac.authorization.k8s.io/v1/namespaces/" + url.PathEscape(namespace) + "/" + resource
}
