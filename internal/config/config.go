// Package config holds the prototype's endpoints. Every value can be overridden by env.
package config

import (
	"os"
	"path/filepath"
)

func Env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func Var(name string) string {
	return filepath.Join(Env("SEALED_HOME", "."), "var", name)
}

var (
	KeysvcURL     = Env("KEYSVC_URL", "http://127.0.0.1:7101")
	CollectorURL  = Env("COLLECTOR_URL", "http://127.0.0.1:7102")
	AggregatorURL = Env("AGGREGATOR_URL", "http://127.0.0.1:7103")
	AgentURL      = Env("AGENT_URL", "http://127.0.0.1:7104") // the fake agent's harness endpoint

	// Where the TUI follows events with kubectl logs.
	KubeContext = Env("KUBE_CONTEXT", "kind-sealed")
	Namespace   = Env("NAMESPACE", "sealed-logs")

	CHAddr = Env("CH_ADDR", "127.0.0.1:19000")
	CHHTTP = Env("CH_HTTP", "http://127.0.0.1:18123")
	CHUser = Env("CH_USER", "sealed")
	CHPass = Env("CH_PASS", "sealed")

	MinioEndpoint = Env("MINIO_ENDPOINT", "127.0.0.1:19100")
	MinioUser     = Env("MINIO_USER", "sealed")
	MinioPass     = Env("MINIO_PASS", "sealed-secret")
	Bucket        = Env("BUCKET", "sealed-logs")

	BaoAddr  = Env("BAO_ADDR", "http://127.0.0.1:18200")
	BaoToken = Env("BAO_TOKEN", "root")

	DemoProject = Env("DEMO_PROJECT", "p_demo")
)
