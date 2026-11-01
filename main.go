package main

import (
	"flag"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	observerv1alpha1 "github.com/premisan/kube-blackbox/api/v1alpha1"
	"github.com/premisan/kube-blackbox/pkg/ai"
	"github.com/premisan/kube-blackbox/pkg/analyzer"
	"github.com/premisan/kube-blackbox/pkg/controller"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(observerv1alpha1.AddToScheme(scheme))
}

func main() {
	var metricsAddr string
	var probeAddr string
	var enableLeaderElection bool
	var maxHistoryPerContainer int
	var historyTTL time.Duration
	var leaderElectionNamespace string

	// AI and localization flags
	var enableAI bool
	var aiProvider string
	var aiEndpoint string
	var aiModel string
	var aiAPIKey string
	var analysisLanguage string
	var logTailLines int64

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&leaderElectionNamespace, "leader-election-namespace", "kube-blackbox",
		"Namespace in which to manage the leader election lease.")
	flag.IntVar(&maxHistoryPerContainer, "max-history-per-container", 5, "Maximum number of PodRestartHistory records to retain per container.")
	flag.DurationVar(&historyTTL, "history-ttl", 7*24*time.Hour, "Time-to-live duration for PodRestartHistory records before garbage collection (e.g. 168h for 7 days).")

	flag.BoolVar(&enableAI, "enable-ai", true, "Enable local AI semantic reasoning and failure cascade synthesis.")
	flag.StringVar(&aiProvider, "ai-provider", "embedded", "AI provider (embedded, ollama, http, openai).")
	flag.StringVar(&aiEndpoint, "ai-endpoint", "http://localhost:11434/v1", "OpenAI-compatible / Ollama API endpoint.")
	flag.StringVar(&aiModel, "ai-model", "qwen2.5-coder:0.5b", "AI model identifier for deep semantic reasoning.")
	flag.StringVar(&aiAPIKey, "ai-api-key", "", "API key for external AI providers.")
	flag.StringVar(&analysisLanguage, "analysis-language", "en", "Default language for diagnosis and AI insights (en, ko, ja, zh, etc.).")
	flag.Int64Var(&logTailLines, "log-tail-lines", 500, "Number of previous container log lines to tail and analyze.")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	// Environment variable overrides
	if envLang := os.Getenv("ANALYSIS_LANGUAGE"); envLang != "" {
		analysisLanguage = envLang
	}
	if envAI := os.Getenv("ENABLE_AI"); envAI == "true" {
		enableAI = true
	} else if envAI == "false" {
		enableAI = false
	}
	if envProvider := os.Getenv("AI_PROVIDER"); envProvider != "" {
		aiProvider = envProvider
	}
	if envEndpoint := os.Getenv("AI_ENDPOINT"); envEndpoint != "" {
		aiEndpoint = envEndpoint
	}
	if envModel := os.Getenv("AI_MODEL"); envModel != "" {
		aiModel = envModel
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	cfg := ctrl.GetConfigOrDie()

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		setupLog.Error(err, "unable to create kubernetes client")
		os.Exit(1)
	}

	if envNs := os.Getenv("POD_NAMESPACE"); envNs != "" {
		leaderElectionNamespace = envNs
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        "kube-blackbox-leader-election",
		LeaderElectionNamespace: leaderElectionNamespace,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	diagnosticEngine := analyzer.NewDiagnosticEngine()

	aiCfg := ai.Config{
		Enabled:         enableAI,
		Provider:        aiProvider,
		Endpoint:        aiEndpoint,
		Model:           aiModel,
		APIKey:          aiAPIKey,
		DefaultLanguage: analysisLanguage,
		TimeoutSeconds:  12,
	}
	aiEngine := ai.NewEngine(aiCfg)

	setupLog.Info("Configured Kube-Blackbox controller",
		"enableAI", enableAI,
		"aiProvider", aiProvider,
		"analysisLanguage", analysisLanguage,
		"logTailLines", logTailLines,
		"maxHistory", maxHistoryPerContainer,
		"historyTTL", historyTTL.String(),
	)

	podReconciler := &controller.PodReconciler{
		Client:                 mgr.GetClient(),
		KubeClient:             kubeClient,
		Scheme:                 mgr.GetScheme(),
		Engine:                 diagnosticEngine,
		AIEngine:               aiEngine,
		DefaultLanguage:        analysisLanguage,
		LogTailLines:           logTailLines,
		MaxHistoryPerContainer: maxHistoryPerContainer,
		HistoryTTL:             historyTTL,
	}

	if err = podReconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Pod")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
