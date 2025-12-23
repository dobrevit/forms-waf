-- defense_profiles_attack_vectors.lua
-- Attack vector-specific defense profiles
-- Each profile focuses on detecting a specific type of attack

local _M = {}

-- Bot Detection Profile
-- Focuses on detecting automated traffic (bots, scrapers, headless browsers)
local BOT_DETECTION_PROFILE = {
    id = "bot-detection",
    name = "Bot Detection",
    description = "Detects automated traffic using timing analysis, behavioral patterns, and browser fingerprinting.",
    enabled = true,
    builtin = true,
    priority = 100,

    graph = {
        nodes = {
            -- Start
            {
                id = "start",
                type = "start",
                position = {x = 50, y = 200},
                outputs = {next = "timing_token"}
            },

            -- Timing Token (bots often submit too fast or ignore JS)
            {
                id = "timing_token",
                type = "defense",
                defense = "timing_token",
                position = {x = 200, y = 200},
                config = {output_mode = "score"},
                outputs = {continue = "behavioral"}
            },

            -- Behavioral Tracking (detects bot-like patterns)
            {
                id = "behavioral",
                type = "defense",
                defense = "behavioral",
                position = {x = 350, y = 200},
                config = {output_mode = "score"},
                outputs = {continue = "fingerprint"}
            },

            -- Fingerprint Profile (validates browser fingerprint)
            {
                id = "fingerprint",
                type = "defense",
                defense = "fingerprint",
                position = {x = 500, y = 200},
                config = {output_mode = "both"},
                outputs = {
                    blocked = "action_block",
                    continue = "header_consistency"
                }
            },

            -- Header Consistency (bots often have inconsistent headers)
            {
                id = "header_consistency",
                type = "defense",
                defense = "header_consistency",
                position = {x = 650, y = 200},
                config = {output_mode = "score"},
                outputs = {continue = "score_sum"}
            },

            -- Sum all scores
            {
                id = "score_sum",
                type = "operator",
                operator = "sum",
                position = {x = 800, y = 200},
                inputs = {"timing_token", "behavioral", "fingerprint", "header_consistency"},
                outputs = {next = "threshold_branch"}
            },

            -- Branch based on total score
            {
                id = "threshold_branch",
                type = "operator",
                operator = "threshold_branch",
                position = {x = 950, y = 200},
                config = {
                    ranges = {
                        {min = 0, max = 30, output = "low"},
                        {min = 30, max = 60, output = "medium"},
                        {min = 60, max = 85, output = "high"},
                        {min = 85, max = nil, output = "critical"}
                    }
                },
                outputs = {
                    low = "action_allow",
                    medium = "action_flag",
                    high = "action_captcha",
                    critical = "action_block"
                }
            },

            -- Action nodes
            {
                id = "action_allow",
                type = "action",
                action = "allow",
                position = {x = 1100, y = 100}
            },
            {
                id = "action_flag",
                type = "action",
                action = "flag",
                position = {x = 1100, y = 200},
                config = {flag_label = "bot_suspect"}
            },
            {
                id = "action_captcha",
                type = "action",
                action = "captcha",
                position = {x = 1100, y = 300}
            },
            {
                id = "action_block",
                type = "action",
                action = "block",
                position = {x = 1100, y = 400},
                config = {http_status = 403}
            }
        }
    },

    settings = {
        default_action = "allow",
        max_execution_time_ms = 50
    }
}

-- Spam Detection Profile
-- Focuses on detecting form spam (honeypots, keywords, patterns)
local SPAM_DETECTION_PROFILE = {
    id = "spam-detection",
    name = "Spam Detection",
    description = "Detects form spam using honeypots, keyword filtering, pattern matching, and disposable email detection.",
    enabled = true,
    builtin = true,
    priority = 90,

    graph = {
        nodes = {
            -- Start
            {
                id = "start",
                type = "start",
                position = {x = 50, y = 200},
                outputs = {next = "honeypot"}
            },

            -- Honeypot (immediate block if filled)
            {
                id = "honeypot",
                type = "defense",
                defense = "honeypot",
                position = {x = 200, y = 200},
                config = {output_mode = "binary"},
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
                position = {x = 350, y = 200},
                config = {output_mode = "both"},
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
                position = {x = 500, y = 200},
                config = {output_mode = "score"},
                outputs = {continue = "disposable_email"}
            },

            -- Disposable Email Detection
            {
                id = "disposable_email",
                type = "defense",
                defense = "disposable_email",
                position = {x = 650, y = 200},
                config = {output_mode = "both"},
                outputs = {
                    blocked = "action_block",
                    continue = "score_sum"
                }
            },

            -- Sum scores
            {
                id = "score_sum",
                type = "operator",
                operator = "sum",
                position = {x = 800, y = 200},
                inputs = {"keyword_filter", "pattern_scan", "disposable_email"},
                outputs = {next = "threshold_branch"}
            },

            -- Branch based on score
            {
                id = "threshold_branch",
                type = "operator",
                operator = "threshold_branch",
                position = {x = 950, y = 200},
                config = {
                    ranges = {
                        {min = 0, max = 25, output = "low"},
                        {min = 25, max = 50, output = "medium"},
                        {min = 50, max = 75, output = "high"},
                        {min = 75, max = nil, output = "critical"}
                    }
                },
                outputs = {
                    low = "action_allow",
                    medium = "action_flag",
                    high = "action_captcha",
                    critical = "action_block"
                }
            },

            -- Actions
            {
                id = "action_allow",
                type = "action",
                action = "allow",
                position = {x = 1100, y = 100}
            },
            {
                id = "action_flag",
                type = "action",
                action = "flag",
                position = {x = 1100, y = 200},
                config = {flag_label = "spam_suspect"}
            },
            {
                id = "action_captcha",
                type = "action",
                action = "captcha",
                position = {x = 1100, y = 300}
            },
            {
                id = "action_block",
                type = "action",
                action = "block",
                position = {x = 1100, y = 400},
                config = {http_status = 403}
            }
        }
    },

    settings = {
        default_action = "allow",
        max_execution_time_ms = 50
    }
}

-- Credential Stuffing Detection Profile
-- Focuses on detecting login abuse (rapid attempts, known bad IPs, behavioral anomalies)
local CREDENTIAL_STUFFING_PROFILE = {
    id = "credential-stuffing",
    name = "Credential Stuffing Detection",
    description = "Detects credential stuffing attacks using timing analysis, IP reputation, and behavioral patterns.",
    enabled = true,
    builtin = true,
    priority = 80,

    graph = {
        nodes = {
            -- Start
            {
                id = "start",
                type = "start",
                position = {x = 50, y = 200},
                outputs = {next = "ip_reputation"}
            },

            -- IP Reputation (known bad actors)
            {
                id = "ip_reputation",
                type = "defense",
                defense = "ip_reputation",
                position = {x = 200, y = 200},
                config = {output_mode = "both"},
                outputs = {
                    blocked = "action_tarpit",
                    continue = "timing_token"
                }
            },

            -- Timing Token (rapid submissions)
            {
                id = "timing_token",
                type = "defense",
                defense = "timing_token",
                position = {x = 350, y = 200},
                config = {output_mode = "score"},
                outputs = {continue = "behavioral"}
            },

            -- Behavioral Tracking
            {
                id = "behavioral",
                type = "defense",
                defense = "behavioral",
                position = {x = 500, y = 200},
                config = {output_mode = "score"},
                outputs = {continue = "field_anomalies"}
            },

            -- Field Anomalies (unusual field content)
            {
                id = "field_anomalies",
                type = "defense",
                defense = "field_anomalies",
                position = {x = 650, y = 200},
                config = {output_mode = "score"},
                outputs = {continue = "score_sum"}
            },

            -- Sum scores
            {
                id = "score_sum",
                type = "operator",
                operator = "sum",
                position = {x = 800, y = 200},
                inputs = {"ip_reputation", "timing_token", "behavioral", "field_anomalies"},
                outputs = {next = "threshold_branch"}
            },

            -- Branch based on score
            {
                id = "threshold_branch",
                type = "operator",
                operator = "threshold_branch",
                position = {x = 950, y = 200},
                config = {
                    ranges = {
                        {min = 0, max = 20, output = "low"},
                        {min = 20, max = 45, output = "medium"},
                        {min = 45, max = 70, output = "high"},
                        {min = 70, max = nil, output = "critical"}
                    }
                },
                outputs = {
                    low = "action_allow",
                    medium = "action_flag",
                    high = "action_captcha",
                    critical = "action_tarpit"
                }
            },

            -- Actions
            {
                id = "action_allow",
                type = "action",
                action = "allow",
                position = {x = 1100, y = 100}
            },
            {
                id = "action_flag",
                type = "action",
                action = "flag",
                position = {x = 1100, y = 200},
                config = {flag_label = "credential_stuffing_suspect"}
            },
            {
                id = "action_captcha",
                type = "action",
                action = "captcha",
                position = {x = 1100, y = 300}
            },
            {
                id = "action_tarpit",
                type = "action",
                action = "tarpit",
                position = {x = 1100, y = 400},
                config = {delay_seconds = 10, then_action = "block"}
            }
        }
    },

    settings = {
        default_action = "allow",
        max_execution_time_ms = 50
    }
}

-- API Abuse Detection Profile
-- Focuses on detecting API abuse (rate limiting, geographic anomalies, IP reputation)
local API_ABUSE_PROFILE = {
    id = "api-abuse",
    name = "API Abuse Detection",
    description = "Detects API abuse using IP reputation, geographic analysis, and behavioral tracking.",
    enabled = true,
    builtin = true,
    priority = 70,

    graph = {
        nodes = {
            -- Start
            {
                id = "start",
                type = "start",
                position = {x = 50, y = 200},
                outputs = {next = "ip_allowlist"}
            },

            -- IP Allowlist (trusted API clients)
            {
                id = "ip_allowlist",
                type = "defense",
                defense = "ip_allowlist",
                position = {x = 200, y = 200},
                outputs = {
                    allowed = "action_allow",
                    continue = "ip_reputation"
                }
            },

            -- IP Reputation
            {
                id = "ip_reputation",
                type = "defense",
                defense = "ip_reputation",
                position = {x = 350, y = 200},
                config = {output_mode = "both"},
                outputs = {
                    blocked = "action_block",
                    continue = "geoip"
                }
            },

            -- GeoIP (block high-risk countries for API)
            {
                id = "geoip",
                type = "defense",
                defense = "geoip",
                position = {x = 500, y = 200},
                config = {output_mode = "both"},
                outputs = {
                    blocked = "action_block",
                    continue = "behavioral"
                }
            },

            -- Behavioral Tracking (API-specific patterns)
            {
                id = "behavioral",
                type = "defense",
                defense = "behavioral",
                position = {x = 650, y = 200},
                config = {output_mode = "score"},
                outputs = {continue = "score_sum"}
            },

            -- Sum scores
            {
                id = "score_sum",
                type = "operator",
                operator = "sum",
                position = {x = 800, y = 200},
                inputs = {"ip_reputation", "geoip", "behavioral"},
                outputs = {next = "threshold_branch"}
            },

            -- Branch based on score
            {
                id = "threshold_branch",
                type = "operator",
                operator = "threshold_branch",
                position = {x = 950, y = 200},
                config = {
                    ranges = {
                        {min = 0, max = 30, output = "low"},
                        {min = 30, max = 60, output = "medium"},
                        {min = 60, max = nil, output = "high"}
                    }
                },
                outputs = {
                    low = "action_allow",
                    medium = "action_flag",
                    high = "action_block"
                }
            },

            -- Actions
            {
                id = "action_allow",
                type = "action",
                action = "allow",
                position = {x = 1100, y = 100}
            },
            {
                id = "action_flag",
                type = "action",
                action = "flag",
                position = {x = 1100, y = 200},
                config = {flag_label = "api_abuse_suspect"}
            },
            {
                id = "action_block",
                type = "action",
                action = "block",
                position = {x = 1100, y = 300},
                config = {http_status = 429}
            }
        }
    },

    settings = {
        default_action = "allow",
        max_execution_time_ms = 30
    }
}

-- Content Filter Profile
-- Focuses on filtering bad content (keywords, hashes, expected fields)
local CONTENT_FILTER_PROFILE = {
    id = "content-filter",
    name = "Content Filter",
    description = "Filters bad content using keyword matching, content hashing, and expected fields validation.",
    enabled = true,
    builtin = true,
    priority = 85,

    graph = {
        nodes = {
            -- Start
            {
                id = "start",
                type = "start",
                position = {x = 50, y = 200},
                outputs = {next = "keyword_filter"}
            },

            -- Keyword Filter (blocked words)
            {
                id = "keyword_filter",
                type = "defense",
                defense = "keyword_filter",
                position = {x = 200, y = 200},
                config = {output_mode = "both"},
                outputs = {
                    blocked = "action_block",
                    continue = "content_hash"
                }
            },

            -- Content Hash (known bad content)
            {
                id = "content_hash",
                type = "defense",
                defense = "content_hash",
                position = {x = 350, y = 200},
                config = {output_mode = "binary"},
                outputs = {
                    blocked = "action_block",
                    continue = "expected_fields"
                }
            },

            -- Expected Fields (validate structure)
            {
                id = "expected_fields",
                type = "defense",
                defense = "expected_fields",
                position = {x = 500, y = 200},
                config = {output_mode = "both"},
                outputs = {
                    blocked = "action_block",
                    continue = "action_allow"
                }
            },

            -- Actions
            {
                id = "action_allow",
                type = "action",
                action = "allow",
                position = {x = 650, y = 200}
            },
            {
                id = "action_block",
                type = "action",
                action = "block",
                position = {x = 650, y = 350},
                config = {http_status = 403}
            }
        }
    },

    settings = {
        default_action = "allow",
        max_execution_time_ms = 30
    }
}

-- All attack vector profiles
_M.PROFILES = {
    BOT_DETECTION_PROFILE,
    SPAM_DETECTION_PROFILE,
    CREDENTIAL_STUFFING_PROFILE,
    API_ABUSE_PROFILE,
    CONTENT_FILTER_PROFILE
}

-- Get all attack vector profiles
function _M.get_all()
    return _M.PROFILES
end

-- Get a specific profile by ID
function _M.get(id)
    for _, profile in ipairs(_M.PROFILES) do
        if profile.id == id then
            return profile
        end
    end
    return nil
end

-- List all attack vector profile IDs
function _M.list_ids()
    local ids = {}
    for _, profile in ipairs(_M.PROFILES) do
        table.insert(ids, profile.id)
    end
    return ids
end

return _M
