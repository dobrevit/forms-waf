-- defense_profiles_builtins.lua
-- Built-in defense profiles

local _M = {}

-- Built-in profile version - increment when making changes to ensure Redis updates
local BUILTIN_VERSION = 3  -- v3: Fixed High-Value profile orphan flag actions

-- Legacy profile: mirrors current waf_handler.lua execution order exactly
-- This is the default profile for backward compatibility
local LEGACY_PROFILE = {
    id = "legacy",
    name = "Legacy (Backward Compatible)",
    description = "Mirrors the original waf_handler.lua execution order. Use for migration compatibility.",
    enabled = true,
    builtin = true,
    builtin_version = BUILTIN_VERSION,
    priority = 1000,

    graph = {
        nodes = {
            -- Start node
            {
                id = "start",
                type = "start",
                position = {x = 50, y = 300},
                outputs = {next = "ip_allowlist"}
            },

            -- IP Allowlist (first check)
            {
                id = "ip_allowlist",
                type = "defense",
                defense = "ip_allowlist",
                position = {x = 150, y = 300},
                outputs = {
                    allowed = "action_allow",
                    continue = "geoip"
                }
            },

            -- GeoIP check
            {
                id = "geoip",
                type = "defense",
                defense = "geoip",
                position = {x = 250, y = 300},
                outputs = {
                    blocked = "action_block",
                    continue = "ip_reputation"
                }
            },

            -- IP Reputation
            {
                id = "ip_reputation",
                type = "defense",
                defense = "ip_reputation",
                position = {x = 350, y = 300},
                outputs = {
                    blocked = "action_block",
                    continue = "timing_token"
                }
            },

            -- Timing Token
            {
                id = "timing_token",
                type = "defense",
                defense = "timing_token",
                position = {x = 450, y = 300},
                outputs = {continue = "behavioral"}
            },

            -- Behavioral Tracking
            {
                id = "behavioral",
                type = "defense",
                defense = "behavioral",
                position = {x = 550, y = 300},
                outputs = {continue = "honeypot"}
            },

            -- Honeypot
            {
                id = "honeypot",
                type = "defense",
                defense = "honeypot",
                position = {x = 650, y = 300},
                outputs = {
                    blocked = "action_block",
                    continue = "keyword_filter"
                }
            },

            -- Keyword Filter
            {
                id = "keyword_filter",
                type = "defense",
                defense = "keyword_filter",
                position = {x = 750, y = 300},
                outputs = {
                    blocked = "action_block",
                    continue = "content_hash"
                }
            },

            -- Content Hash
            {
                id = "content_hash",
                type = "defense",
                defense = "content_hash",
                position = {x = 850, y = 300},
                outputs = {
                    blocked = "action_block",
                    continue = "expected_fields"
                }
            },

            -- Expected Fields
            {
                id = "expected_fields",
                type = "defense",
                defense = "expected_fields",
                position = {x = 950, y = 300},
                outputs = {
                    blocked = "action_block",
                    continue = "pattern_scan"
                }
            },

            -- Pattern Scanner
            {
                id = "pattern_scan",
                type = "defense",
                defense = "pattern_scan",
                position = {x = 1050, y = 300},
                outputs = {continue = "disposable_email"}
            },

            -- Disposable Email
            {
                id = "disposable_email",
                type = "defense",
                defense = "disposable_email",
                position = {x = 1150, y = 300},
                outputs = {
                    blocked = "action_block",
                    continue = "field_anomalies"
                }
            },

            -- Field Anomalies
            {
                id = "field_anomalies",
                type = "defense",
                defense = "field_anomalies",
                position = {x = 1250, y = 300},
                outputs = {continue = "field_learner"}
            },

            -- Field Learner (observation - non-blocking, records field names for learning)
            {
                id = "field_learner",
                type = "observation",
                observation = "field_learner",
                position = {x = 1300, y = 400},
                outputs = {continue = "fingerprint"}
            },

            -- Fingerprint Profiles
            {
                id = "fingerprint",
                type = "defense",
                defense = "fingerprint",
                position = {x = 1350, y = 300},
                outputs = {
                    blocked = "action_block",
                    continue = "sum_all"
                }
            },

            -- Sum all scores
            {
                id = "sum_all",
                type = "operator",
                operator = "sum",
                position = {x = 1450, y = 300},
                inputs = {"geoip", "ip_reputation", "timing_token", "behavioral", "honeypot", "keyword_filter", "expected_fields", "pattern_scan", "disposable_email", "field_anomalies", "fingerprint"},
                outputs = {next = "threshold_check"}
            },

            -- Threshold check
            {
                id = "threshold_check",
                type = "operator",
                operator = "threshold_branch",
                position = {x = 1550, y = 300},
                config = {
                    ranges = {
                        {min = 0, max = 80, output = "low"},
                        {min = 80, max = nil, output = "high"}
                    }
                },
                outputs = {
                    low = "action_allow",
                    high = "action_block"
                }
            },

            -- Action: Allow
            {
                id = "action_allow",
                type = "action",
                action = "allow",
                position = {x = 1650, y = 200}
            },

            -- Action: Block
            {
                id = "action_block",
                type = "action",
                action = "block",
                position = {x = 1650, y = 400},
                config = {reason = "spam_threshold_exceeded"}
            }
        }
    },

    settings = {
        default_action = "allow",
        max_execution_time_ms = 100
    }
}

-- Balanced Web profile: good for typical web forms
local BALANCED_WEB_PROFILE = {
    id = "balanced-web",
    name = "Balanced Web Protection",
    description = "Balanced protection for web forms with CAPTCHA for medium scores.",
    enabled = true,
    builtin = true,
    builtin_version = BUILTIN_VERSION,
    priority = 100,

    graph = {
        nodes = {
            {
                id = "start",
                type = "start",
                position = {x = 50, y = 300},
                outputs = {next = "ip_allowlist"}
            },
            {
                id = "ip_allowlist",
                type = "defense",
                defense = "ip_allowlist",
                position = {x = 150, y = 300},
                outputs = {allowed = "action_allow", continue = "geoip"}
            },

            -- Early checks: GeoIP + IP Reputation
            {
                id = "geoip",
                type = "defense",
                defense = "geoip",
                position = {x = 300, y = 200},
                outputs = {blocked = "action_block", continue = "ip_reputation"}
            },
            {
                id = "ip_reputation",
                type = "defense",
                defense = "ip_reputation",
                position = {x = 450, y = 200},
                outputs = {blocked = "action_block", continue = "sum_early"}
            },
            {
                id = "sum_early",
                type = "operator",
                operator = "sum",
                position = {x = 600, y = 200},
                inputs = {"geoip", "ip_reputation"},
                outputs = {next = "early_threshold"}
            },
            {
                id = "early_threshold",
                type = "operator",
                operator = "threshold_branch",
                position = {x = 750, y = 200},
                config = {
                    ranges = {
                        {min = 0, max = 50, output = "low"},
                        {min = 50, max = 100, output = "medium"},
                        {min = 100, max = nil, output = "high"}
                    }
                },
                outputs = {
                    low = "timing_token",
                    medium = "action_captcha",
                    high = "action_block"
                }
            },

            -- Content checks
            {
                id = "timing_token",
                type = "defense",
                defense = "timing_token",
                position = {x = 300, y = 400},
                outputs = {continue = "honeypot"}
            },
            {
                id = "honeypot",
                type = "defense",
                defense = "honeypot",
                position = {x = 450, y = 400},
                outputs = {blocked = "action_block", continue = "keyword_filter"}
            },
            {
                id = "keyword_filter",
                type = "defense",
                defense = "keyword_filter",
                position = {x = 600, y = 400},
                outputs = {blocked = "action_block", continue = "pattern_scan"}
            },
            {
                id = "pattern_scan",
                type = "defense",
                defense = "pattern_scan",
                position = {x = 750, y = 400},
                outputs = {continue = "field_anomalies"}
            },
            {
                id = "field_anomalies",
                type = "defense",
                defense = "field_anomalies",
                position = {x = 900, y = 400},
                outputs = {continue = "fingerprint"}
            },
            {
                id = "fingerprint",
                type = "defense",
                defense = "fingerprint",
                position = {x = 1050, y = 400},
                outputs = {blocked = "action_block", continue = "sum_content"}
            },
            {
                id = "sum_content",
                type = "operator",
                operator = "sum",
                position = {x = 1200, y = 400},
                inputs = {"timing_token", "honeypot", "keyword_filter", "pattern_scan", "field_anomalies", "fingerprint", "sum_early"},
                outputs = {next = "final_threshold"}
            },
            {
                id = "final_threshold",
                type = "operator",
                operator = "threshold_branch",
                position = {x = 1350, y = 400},
                config = {
                    ranges = {
                        {min = 0, max = 50, output = "low"},
                        {min = 50, max = 80, output = "medium"},
                        {min = 80, max = nil, output = "high"}
                    }
                },
                outputs = {
                    low = "action_allow",
                    medium = "action_captcha",
                    high = "action_block"
                }
            },

            -- Actions
            {
                id = "action_allow",
                type = "action",
                action = "allow",
                position = {x = 1500, y = 200}
            },
            {
                id = "action_captcha",
                type = "action",
                action = "captcha",
                position = {x = 1500, y = 350}
            },
            {
                id = "action_block",
                type = "action",
                action = "block",
                position = {x = 1500, y = 500},
                config = {reason = "spam_detected"}
            }
        }
    },

    settings = {
        default_action = "allow",
        max_execution_time_ms = 100
    }
}

-- Strict API profile: for API endpoints with tarpit
local STRICT_API_PROFILE = {
    id = "strict-api",
    name = "Strict API Protection",
    description = "High-security profile for API endpoints. Uses tarpit for suspicious requests.",
    enabled = true,
    builtin = true,
    builtin_version = BUILTIN_VERSION,
    priority = 50,

    graph = {
        nodes = {
            {
                id = "start",
                type = "start",
                position = {x = 50, y = 300},
                outputs = {next = "ip_allowlist"}
            },
            {
                id = "ip_allowlist",
                type = "defense",
                defense = "ip_allowlist",
                position = {x = 150, y = 300},
                outputs = {allowed = "action_allow", continue = "ip_reputation"}
            },

            -- IP Reputation first (most effective for API abuse)
            {
                id = "ip_reputation",
                type = "defense",
                defense = "ip_reputation",
                position = {x = 300, y = 300},
                outputs = {blocked = "action_tarpit_long", continue = "geoip"}
            },
            {
                id = "geoip",
                type = "defense",
                defense = "geoip",
                position = {x = 450, y = 300},
                outputs = {blocked = "action_block", continue = "sum_ip"}
            },
            {
                id = "sum_ip",
                type = "operator",
                operator = "sum",
                position = {x = 600, y = 300},
                inputs = {"ip_reputation", "geoip"},
                outputs = {next = "ip_threshold"}
            },
            {
                id = "ip_threshold",
                type = "operator",
                operator = "threshold_branch",
                position = {x = 750, y = 300},
                config = {
                    ranges = {
                        {min = 0, max = 30, output = "low"},
                        {min = 30, max = 60, output = "medium"},
                        {min = 60, max = 100, output = "high"},
                        {min = 100, max = nil, output = "critical"}
                    }
                },
                outputs = {
                    low = "fingerprint",
                    medium = "action_flag",
                    high = "action_tarpit",
                    critical = "action_block"
                }
            },

            -- Content checks
            {
                id = "fingerprint",
                type = "defense",
                defense = "fingerprint",
                position = {x = 300, y = 500},
                outputs = {blocked = "action_block", continue = "header_consistency"}
            },
            {
                id = "header_consistency",
                type = "defense",
                defense = "header_consistency",
                position = {x = 450, y = 500},
                outputs = {continue = "expected_fields"}
            },
            {
                id = "expected_fields",
                type = "defense",
                defense = "expected_fields",
                position = {x = 600, y = 500},
                outputs = {blocked = "action_block", continue = "content_hash"}
            },
            {
                id = "content_hash",
                type = "defense",
                defense = "content_hash",
                position = {x = 750, y = 500},
                outputs = {blocked = "action_block", continue = "sum_content"}
            },
            {
                id = "sum_content",
                type = "operator",
                operator = "sum",
                position = {x = 900, y = 500},
                inputs = {"fingerprint", "header_consistency", "expected_fields", "sum_ip"},
                outputs = {next = "final_threshold"}
            },
            {
                id = "final_threshold",
                type = "operator",
                operator = "threshold_branch",
                position = {x = 1050, y = 500},
                config = {
                    ranges = {
                        {min = 0, max = 40, output = "low"},
                        {min = 40, max = 70, output = "medium"},
                        {min = 70, max = 100, output = "high"},
                        {min = 100, max = nil, output = "critical"}
                    }
                },
                outputs = {
                    low = "action_allow",
                    medium = "action_flag",
                    high = "action_tarpit",
                    critical = "action_block"
                }
            },

            -- Actions
            {
                id = "action_allow",
                type = "action",
                action = "allow",
                position = {x = 1200, y = 150}
            },
            {
                id = "action_flag",
                type = "action",
                action = "flag",
                position = {x = 1200, y = 300},
                config = {reason = "api_suspicious", score = 0}
            },
            {
                id = "action_tarpit",
                type = "action",
                action = "tarpit",
                position = {x = 1200, y = 450},
                config = {delay_seconds = 5, then_action = "block"}
            },
            {
                id = "action_tarpit_long",
                type = "action",
                action = "tarpit",
                position = {x = 450, y = 100},
                config = {delay_seconds = 10, then_action = "block"}
            },
            {
                id = "action_block",
                type = "action",
                action = "block",
                position = {x = 1200, y = 600},
                config = {reason = "api_abuse_detected"}
            }
        }
    },

    settings = {
        default_action = "allow",
        max_execution_time_ms = 50  -- Faster timeout for APIs
    }
}

-- Permissive profile: for high-traffic, low-risk pages
local PERMISSIVE_PROFILE = {
    id = "permissive",
    name = "Permissive (Low Security)",
    description = "Minimal protection for high-traffic, low-risk pages. Only critical checks.",
    enabled = true,
    builtin = true,
    builtin_version = BUILTIN_VERSION,
    priority = 200,

    graph = {
        nodes = {
            {
                id = "start",
                type = "start",
                position = {x = 50, y = 300},
                outputs = {next = "ip_allowlist"}
            },
            {
                id = "ip_allowlist",
                type = "defense",
                defense = "ip_allowlist",
                position = {x = 150, y = 300},
                outputs = {allowed = "action_allow", continue = "ip_reputation"}
            },
            {
                id = "ip_reputation",
                type = "defense",
                defense = "ip_reputation",
                position = {x = 300, y = 300},
                outputs = {blocked = "action_block", continue = "honeypot"}
            },
            {
                id = "honeypot",
                type = "defense",
                defense = "honeypot",
                position = {x = 450, y = 300},
                outputs = {blocked = "action_block", continue = "keyword_filter"}
            },
            {
                id = "keyword_filter",
                type = "defense",
                defense = "keyword_filter",
                position = {x = 600, y = 300},
                outputs = {blocked = "action_block", continue = "content_hash"}
            },
            {
                id = "content_hash",
                type = "defense",
                defense = "content_hash",
                position = {x = 750, y = 300},
                outputs = {blocked = "action_block", continue = "sum_all"}
            },
            {
                id = "sum_all",
                type = "operator",
                operator = "sum",
                position = {x = 900, y = 300},
                inputs = {"ip_reputation", "honeypot", "keyword_filter"},
                outputs = {next = "threshold_check"}
            },
            {
                id = "threshold_check",
                type = "operator",
                operator = "threshold_branch",
                position = {x = 1050, y = 300},
                config = {
                    ranges = {
                        {min = 0, max = 120, output = "low"},
                        {min = 120, max = nil, output = "high"}
                    }
                },
                outputs = {
                    low = "action_allow",
                    high = "action_block"
                }
            },
            {
                id = "action_allow",
                type = "action",
                action = "allow",
                position = {x = 1200, y = 200}
            },
            {
                id = "action_block",
                type = "action",
                action = "block",
                position = {x = 1200, y = 400},
                config = {reason = "critical_violation"}
            }
        }
    },

    settings = {
        default_action = "allow",
        max_execution_time_ms = 30  -- Very fast
    }
}

-- High-Value profile: for payment/signup forms with staged response
local HIGH_VALUE_PROFILE = {
    id = "high-value",
    name = "High-Value Transaction Protection",
    description = "Maximum protection for payment and signup forms. Multi-stage response.",
    enabled = true,
    builtin = true,
    builtin_version = BUILTIN_VERSION,
    priority = 25,

    graph = {
        nodes = {
            {
                id = "start",
                type = "start",
                position = {x = 50, y = 300},
                outputs = {next = "ip_allowlist"}
            },
            {
                id = "ip_allowlist",
                type = "defense",
                defense = "ip_allowlist",
                position = {x = 150, y = 300},
                outputs = {allowed = "action_allow", continue = "geoip"}
            },

            -- Early checks (sequential)
            {
                id = "geoip",
                type = "defense",
                defense = "geoip",
                position = {x = 300, y = 300},
                outputs = {blocked = "action_block", continue = "ip_reputation"}
            },
            {
                id = "ip_reputation",
                type = "defense",
                defense = "ip_reputation",
                position = {x = 450, y = 300},
                outputs = {blocked = "action_tarpit", continue = "sum_early"}
            },
            {
                id = "sum_early",
                type = "operator",
                operator = "sum",
                position = {x = 600, y = 300},
                inputs = {"geoip", "ip_reputation"},
                outputs = {next = "early_threshold"}
            },
            {
                id = "early_threshold",
                type = "operator",
                operator = "threshold_branch",
                position = {x = 750, y = 300},
                config = {
                    ranges = {
                        {min = 0, max = 30, output = "low"},
                        {min = 30, max = 60, output = "medium"},
                        {min = 60, max = nil, output = "high"}
                    }
                },
                outputs = {
                    low = "timing_token",
                    medium = "timing_token",  -- Continue to content checks (score accumulates)
                    high = "action_captcha"
                }
            },

            -- Content layer
            {
                id = "timing_token",
                type = "defense",
                defense = "timing_token",
                position = {x = 300, y = 500},
                outputs = {continue = "behavioral"}
            },
            {
                id = "behavioral",
                type = "defense",
                defense = "behavioral",
                position = {x = 450, y = 500},
                outputs = {continue = "honeypot"}
            },
            {
                id = "honeypot",
                type = "defense",
                defense = "honeypot",
                position = {x = 600, y = 500},
                outputs = {blocked = "action_block", continue = "keyword_filter"}
            },
            {
                id = "keyword_filter",
                type = "defense",
                defense = "keyword_filter",
                position = {x = 750, y = 500},
                outputs = {blocked = "action_block", continue = "content_hash"}
            },
            {
                id = "content_hash",
                type = "defense",
                defense = "content_hash",
                position = {x = 900, y = 500},
                outputs = {blocked = "action_block", continue = "expected_fields"}
            },
            {
                id = "expected_fields",
                type = "defense",
                defense = "expected_fields",
                position = {x = 1050, y = 500},
                outputs = {blocked = "action_block", continue = "pattern_scan"}
            },
            {
                id = "pattern_scan",
                type = "defense",
                defense = "pattern_scan",
                position = {x = 1200, y = 500},
                outputs = {continue = "disposable_email"}
            },
            {
                id = "disposable_email",
                type = "defense",
                defense = "disposable_email",
                position = {x = 1350, y = 500},
                outputs = {blocked = "action_captcha", continue = "field_anomalies"}
            },
            {
                id = "field_anomalies",
                type = "defense",
                defense = "field_anomalies",
                position = {x = 1500, y = 500},
                outputs = {continue = "fingerprint"}
            },
            {
                id = "fingerprint",
                type = "defense",
                defense = "fingerprint",
                position = {x = 1650, y = 500},
                outputs = {blocked = "action_block", continue = "header_consistency"}
            },
            {
                id = "header_consistency",
                type = "defense",
                defense = "header_consistency",
                position = {x = 1800, y = 500},
                outputs = {continue = "sum_content"}
            },
            {
                id = "sum_content",
                type = "operator",
                operator = "sum",
                position = {x = 1950, y = 500},
                inputs = {"sum_early", "timing_token", "behavioral", "honeypot", "keyword_filter", "expected_fields", "pattern_scan", "disposable_email", "field_anomalies", "fingerprint", "header_consistency"},
                outputs = {next = "final_threshold"}
            },
            {
                id = "final_threshold",
                type = "operator",
                operator = "threshold_branch",
                position = {x = 2100, y = 500},
                config = {
                    ranges = {
                        {min = 0, max = 30, output = "very_low"},
                        {min = 30, max = 50, output = "low"},
                        {min = 50, max = 80, output = "medium"},
                        {min = 80, max = 120, output = "high"},
                        {min = 120, max = nil, output = "critical"}
                    }
                },
                outputs = {
                    very_low = "action_allow",
                    low = "action_allow",  -- Low risk: allow (score is logged in headers)
                    medium = "action_captcha",
                    high = "action_tarpit",
                    critical = "action_block"
                }
            },

            -- Actions
            {
                id = "action_allow",
                type = "action",
                action = "allow",
                position = {x = 2250, y = 200}
            },
            {
                id = "action_captcha",
                type = "action",
                action = "captcha",
                position = {x = 2250, y = 500}
            },
            {
                id = "action_tarpit",
                type = "action",
                action = "tarpit",
                position = {x = 2250, y = 650},
                config = {delay_seconds = 10, then_action = "block"}
            },
            {
                id = "action_block",
                type = "action",
                action = "block",
                position = {x = 2250, y = 800},
                config = {reason = "high_value_fraud_detected"}
            }
        }
    },

    settings = {
        default_action = "allow",
        max_execution_time_ms = 150  -- More time for thorough checks
    }
}

-- Monitor-Only profile: for testing/observing without blocking
local MONITOR_ONLY_PROFILE = {
    id = "monitor-only",
    name = "Monitor Only (No Blocking)",
    description = "Runs all checks but never blocks. For testing and observation.",
    enabled = true,
    builtin = true,
    builtin_version = BUILTIN_VERSION,
    priority = 900,

    graph = {
        nodes = {
            {
                id = "start",
                type = "start",
                position = {x = 50, y = 300},
                outputs = {next = "geoip"}
            },
            {
                id = "geoip",
                type = "defense",
                defense = "geoip",
                position = {x = 150, y = 300},
                outputs = {blocked = "sum_all", continue = "ip_reputation"}
            },
            {
                id = "ip_reputation",
                type = "defense",
                defense = "ip_reputation",
                position = {x = 250, y = 300},
                outputs = {blocked = "sum_all", continue = "timing_token"}
            },
            {
                id = "timing_token",
                type = "defense",
                defense = "timing_token",
                position = {x = 350, y = 300},
                outputs = {continue = "behavioral"}
            },
            {
                id = "behavioral",
                type = "defense",
                defense = "behavioral",
                position = {x = 450, y = 300},
                outputs = {continue = "honeypot"}
            },
            {
                id = "honeypot",
                type = "defense",
                defense = "honeypot",
                position = {x = 550, y = 300},
                outputs = {blocked = "sum_all", continue = "keyword_filter"}
            },
            {
                id = "keyword_filter",
                type = "defense",
                defense = "keyword_filter",
                position = {x = 650, y = 300},
                outputs = {blocked = "sum_all", continue = "pattern_scan"}
            },
            {
                id = "pattern_scan",
                type = "defense",
                defense = "pattern_scan",
                position = {x = 750, y = 300},
                outputs = {continue = "field_anomalies"}
            },
            {
                id = "field_anomalies",
                type = "defense",
                defense = "field_anomalies",
                position = {x = 850, y = 300},
                outputs = {continue = "fingerprint"}
            },
            {
                id = "fingerprint",
                type = "defense",
                defense = "fingerprint",
                position = {x = 950, y = 300},
                outputs = {blocked = "sum_all", continue = "sum_all"}
            },
            {
                id = "sum_all",
                type = "operator",
                operator = "sum",
                position = {x = 1050, y = 300},
                inputs = {"geoip", "ip_reputation", "timing_token", "behavioral", "honeypot", "keyword_filter", "pattern_scan", "field_anomalies", "fingerprint"},
                outputs = {next = "action_monitor"}
            },
            {
                id = "action_monitor",
                type = "action",
                action = "monitor",
                position = {x = 1150, y = 300}
            }
        }
    },

    settings = {
        default_action = "monitor",
        max_execution_time_ms = 100
    }
}

-- Export version for redis_sync to check
_M.VERSION = BUILTIN_VERSION

-- Export all built-in profiles (general-purpose)
_M.PROFILES = {
    LEGACY_PROFILE,
    BALANCED_WEB_PROFILE,
    STRICT_API_PROFILE,
    PERMISSIVE_PROFILE,
    HIGH_VALUE_PROFILE,
    MONITOR_ONLY_PROFILE
}

-- Lazy-load attack vector profiles
local _attack_vectors
local function get_attack_vectors()
    if not _attack_vectors then
        local ok, av = pcall(require, "defense_profiles_attack_vectors")
        if ok then
            _attack_vectors = av.PROFILES or {}
        else
            ngx.log(ngx.WARN, "Could not load attack vector profiles: ", av)
            _attack_vectors = {}
        end
    end
    return _attack_vectors
end

-- Get all profiles (general + attack vectors)
function _M.get_all()
    local all = {}
    for _, p in ipairs(_M.PROFILES) do
        table.insert(all, p)
    end
    for _, p in ipairs(get_attack_vectors()) do
        table.insert(all, p)
    end
    return all
end

-- Get profile by ID (check both general and attack vector profiles)
function _M.get(id)
    -- Check general profiles first
    for _, profile in ipairs(_M.PROFILES) do
        if profile.id == id then
            return profile
        end
    end
    -- Check attack vector profiles
    for _, profile in ipairs(get_attack_vectors()) do
        if profile.id == id then
            return profile
        end
    end
    return nil
end

-- Get all profile IDs
function _M.get_ids()
    local ids = {}
    for _, profile in ipairs(_M.PROFILES) do
        table.insert(ids, profile.id)
    end
    for _, profile in ipairs(get_attack_vectors()) do
        table.insert(ids, profile.id)
    end
    return ids
end

return _M
