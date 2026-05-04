package ddoscc

import "time"

// Action represents the result of a unified DDoS/CC check.
type Action int

const (
	ActionAllow          Action = iota
	ActionBlock
	ActionJSChallenge
	ActionEnvFingerprint // Stage 1: env fingerprint, auto-redirect
	ActionPoWChallenge   // Stage 2: proof of work, manual click
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionBlock:
		return "block"
	case ActionJSChallenge:
		return "js_challenge"
	case ActionEnvFingerprint:
		return "env_fingerprint"
	case ActionPoWChallenge:
		return "pow_challenge"
	default:
		return "unknown"
	}
}

// Attack type labels — unified under ddos/cc.
const (
	AttackTypeNone            = ""
	AttackTypeGlobalFlood     = "ddos/cc:global_flood"
	AttackTypeDistributed     = "ddos/cc:distributed"
	AttackTypeConcentrated    = "ddos/cc:concentrated"
	AttackTypeHTTPFlood       = "ddos/cc:http_flood"
	AttackTypeSlowLoris       = "ddos/cc:slowloris"
	AttackTypeGoldenEye       = "ddos/cc:goldeneye"
	AttackTypeSYNFlood        = "ddos/cc:syn_flood"
	AttackTypeUARotation      = "ddos/cc:ua_rotation"
	AttackTypePathConcentration = "ddos/cc:path_concentration"
	AttackTypeBehavior        = "ddos/cc:behavior"
	AttackTypeReputation      = "ddos/cc:reputation"
	AttackTypeChallenge       = "ddos/cc:challenge"
	AttackTypeBlock           = "ddos/cc:block"
)

// Config holds unified DDoS/CC defense settings.
type Config struct {
	Enabled bool

	// Token bucket rate limiting
	RequestsPerSecond int
	BurstSize         int

	// Connection / slowloris
	MaxConnectionsPerIP int
	SlowlorisTimeoutMs  int

	// Global DDoS detection thresholds
	GlobalRateDangerThreshold        float64
	GlobalRateDistributedThreshold   float64
	GlobalDistributedPathThreshold   int
	GlobalConcentratedPathThreshold  int

	// Per-IP sliding window
	MaxRequests   int
	BurstRequests int
	WindowSec     int

	// Behavior fingerprint
	BehaviorScoreThreshold float64
	BehaviorBlockThreshold  float64

	// Path concentration
	PathIPThreshold     int
	PathAvgReqThreshold float64
	PathTimeWindowSec   int

	// IP reputation
	SuspicionBlockThreshold     float64
	SuspicionChallengeThreshold float64
	BlockDurationSec            int
	BlockAcceleration           float64
	MaxBlockCount               int

	// Challenge system
	JSChallengeEnabled      bool
	CaptchaChallengeEnabled  bool
	EnvFingerprintEnabled    bool
	PoWChallengeEnabled      bool
	PoWDifficulty            int

	TrustForwarded bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:                          true,
		RequestsPerSecond:                25,
		BurstSize:                        30,
		MaxConnectionsPerIP:              100,
		SlowlorisTimeoutMs:               30000,
		GlobalRateDangerThreshold:        50,
		GlobalRateDistributedThreshold:   22,
		GlobalDistributedPathThreshold:   30,
		GlobalConcentratedPathThreshold:  3,
		MaxRequests:                      200,
		BurstRequests:                    300,
		WindowSec:                        60,
		BehaviorScoreThreshold:           70,
		BehaviorBlockThreshold:           30,
		PathIPThreshold:                  50,
		PathAvgReqThreshold:              3,
		PathTimeWindowSec:                600,
		SuspicionBlockThreshold:          80,
		SuspicionChallengeThreshold:      50,
		BlockDurationSec:                 600,
		BlockAcceleration:                1.5,
		MaxBlockCount:                    3,
		JSChallengeEnabled:               true,
		CaptchaChallengeEnabled:          true,
		EnvFingerprintEnabled:            true,
		PoWChallengeEnabled:              true,
		PoWDifficulty:                    5,
	}
}

// Detection thresholds used at runtime.
const (
	defaultStatsWindow             = 10 * time.Second
	defaultGoldenEyeMinPath        = 3
	httpFloodRateThreshold         = 20
	httpFloodExtremeRateThreshold  = 40
	httpFloodPureRateThreshold     = 30
	maxTrackedRequests             = 200
	slowlorisMinRate               = 0.1
	slowlorisMinConns              = 3
	bucketSize                     = 5 * time.Second
	maxTrackedIPs                  = 10000
)
