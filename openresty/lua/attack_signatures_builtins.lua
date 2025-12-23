-- attack_signatures_builtins.lua
-- Built-in attack signatures for common attack vectors

local _M = {}

-- Built-in signature version - increment when making changes to ensure Redis updates
local BUILTIN_VERSION = 1

-- WordPress Login Protection
local WORDPRESS_LOGIN = {
    id = "builtin_wordpress_login",
    name = "WordPress Login Protection",
    description = "Blocks known WordPress scanning tools, brute force bots, and credential stuffing attacks targeting wp-login.php",
    enabled = true,
    builtin = true,
    builtin_version = BUILTIN_VERSION,
    priority = 50,

    signatures = {
        -- Fingerprint defense - block known scanner UAs
        fingerprint = {
            blocked_user_agents = {
                "WPScan",
                "nikto",
                "sqlmap",
                "wpscan",
                "wp-scan",
                "WPVulnDB",
            },
            flagged_user_agents = {
                {pattern = "python%-requests", score = 25},
                {pattern = "python%-urllib", score = 25},
                {pattern = "Go%-http%-client", score = 20},
                {pattern = "^curl/", score = 15},
                {pattern = "^wget/", score = 15},
                {pattern = "axios/", score = 10},
                {pattern = "node%-fetch", score = 10},
                {pattern = "libwww%-perl", score = 30},
                {pattern = "mechanize", score = 25},
            },
        },

        -- Keyword filter - block PHP injection attempts
        keyword_filter = {
            blocked_keywords = {
                "<?php",
                "eval(",
                "base64_decode(",
                "system(",
                "exec(",
                "passthru(",
                "shell_exec(",
            },
            flagged_keywords = {
                {keyword = "wp-admin", score = 10},
                {keyword = "xmlrpc", score = 15},
                {keyword = "../", score = 20},
                {keyword = "..\\", score = 20},
            },
        },

        -- Expected fields - WordPress login form structure
        expected_fields = {
            required_fields = {"log", "pwd"},
            forbidden_fields = {"cmd", "exec", "shell", "command", "passthru"},
            max_extra_fields = 5,
        },

        -- Rate limiter - strict limits for login endpoint
        rate_limiter = {
            requests_per_minute = 5,
            requests_per_hour = 30,
            burst_limit = 3,
        },

        -- Header consistency - expect browser-like headers
        header_consistency = {
            required_headers = {"User-Agent"},
            forbidden_headers = {"X-Scanner", "X-Attack"},
        },
    },

    tags = {"wordpress", "login", "brute-force", "cms", "builtin"},
}

-- WordPress Registration Spam Protection
local WORDPRESS_REGISTER = {
    id = "builtin_wordpress_register",
    name = "WordPress Registration Spam",
    description = "Blocks automated user registration bots and spam signups on WordPress sites",
    enabled = true,
    builtin = true,
    builtin_version = BUILTIN_VERSION,
    priority = 50,

    signatures = {
        -- Fingerprint defense - block headless browsers
        fingerprint = {
            blocked_user_agents = {
                "Headless",
                "PhantomJS",
                "Selenium",
                "puppeteer",
                "playwright",
            },
            flagged_user_agents = {
                {pattern = "bot", score = 30},
                {pattern = "crawler", score = 30},
                {pattern = "spider", score = 30},
                {pattern = "scraper", score = 35},
            },
        },

        -- Keyword filter - spam content indicators
        keyword_filter = {
            flagged_keywords = {
                {keyword = "casino", score = 40},
                {keyword = "viagra", score = 40},
                {keyword = "cialis", score = 40},
                {keyword = "cryptocurrency", score = 20},
                {keyword = "bitcoin", score = 15},
                {keyword = "free money", score = 35},
                {keyword = "lottery", score = 30},
                {keyword = "prize winner", score = 35},
                {keyword = "click here", score = 15},
            },
            blocked_patterns = {
                "\\[url=",  -- BBCode links
                "\\[link=",
            },
        },

        -- Disposable email - block temp email domains
        disposable_email = {
            blocked_domains = {
                "tempmail.com",
                "guerrillamail.com",
                "10minutemail.com",
                "throwaway.email",
                "mailinator.com",
                "yopmail.com",
                "fakeinbox.com",
                "trashmail.com",
            },
            blocked_patterns = {
                "%+.*@",  -- Plus-addressing often used for spam
            },
        },

        -- Pattern scan - suspicious URLs in content
        pattern_scan = {
            flagged_patterns = {
                {pattern = "https?://[^%s]+%.ru/", score = 25},
                {pattern = "https?://[^%s]+%.cn/", score = 20},
                {pattern = "https?://[^%s]+%.tk/", score = 30},
                {pattern = "https?://[^%s]+%.xyz/", score = 20},
                {pattern = "https?://bit%.ly/", score = 15},
                {pattern = "https?://tinyurl%.com/", score = 15},
            },
        },

        -- Behavioral - require human-like interaction
        behavioral = {
            min_time_on_page_ms = 3000,
            require_mouse_movement = true,
        },

        -- Rate limiter - prevent mass registration
        rate_limiter = {
            requests_per_minute = 3,
            requests_per_hour = 10,
            burst_limit = 2,
        },

        -- Field anomalies - detect suspicious field values
        field_anomalies = {
            field_rules = {
                {
                    field = "user_login",
                    min_length = 3,
                    max_length = 60,
                },
                {
                    field = "user_email",
                    min_length = 6,
                    max_length = 100,
                },
            },
            max_field_length = 1000,
        },
    },

    tags = {"wordpress", "registration", "spam", "cms", "builtin"},
}

-- WordPress XML-RPC Protection
local WORDPRESS_XMLRPC = {
    id = "builtin_wordpress_xmlrpc",
    name = "WordPress XML-RPC Protection",
    description = "Protects against XML-RPC abuse including pingback attacks, brute force via system.multicall, and DDoS amplification",
    enabled = true,
    builtin = true,
    builtin_version = BUILTIN_VERSION,
    priority = 40,

    signatures = {
        -- Keyword filter - block dangerous XML-RPC methods
        keyword_filter = {
            blocked_keywords = {
                "system.multicall",
                "pingback.ping",
                "wp.getUsersBlogs",
            },
            flagged_keywords = {
                {keyword = "wp.getUsers", score = 30},
                {keyword = "wp.getAuthors", score = 20},
                {keyword = "metaWeblog.getUsersBlogs", score = 25},
            },
        },

        -- Pattern scan - detect brute force patterns
        pattern_scan = {
            blocked_patterns = {
                "<methodCall>.-system%.multicall.-</methodCall>",  -- Multicall brute force
            },
            flagged_patterns = {
                {pattern = "<methodName>wp%.", score = 10},  -- WordPress methods
            },
        },

        -- Rate limiter - very strict for XML-RPC
        rate_limiter = {
            requests_per_minute = 10,
            requests_per_hour = 60,
            burst_limit = 5,
        },

        -- Header consistency
        header_consistency = {
            required_headers = {"Content-Type"},
        },
    },

    tags = {"wordpress", "xmlrpc", "ddos", "amplification", "cms", "builtin"},
}

-- WordPress Comment Spam Protection
local WORDPRESS_COMMENTS = {
    id = "builtin_wordpress_comments",
    name = "WordPress Comment Spam",
    description = "Blocks automated comment spam, trackback spam, and comment form abuse",
    enabled = true,
    builtin = true,
    builtin_version = BUILTIN_VERSION,
    priority = 60,

    signatures = {
        -- Keyword filter - spam indicators
        keyword_filter = {
            flagged_keywords = {
                {keyword = "casino", score = 40},
                {keyword = "viagra", score = 40},
                {keyword = "porn", score = 50},
                {keyword = "xxx", score = 50},
                {keyword = "buy cheap", score = 30},
                {keyword = "discount", score = 15},
                {keyword = "free download", score = 25},
                {keyword = "make money", score = 30},
                {keyword = "work from home", score = 20},
            },
            blocked_patterns = {
                "\\[url=",  -- BBCode
                "\\[link=",
                "<a href=",  -- HTML in comments
            },
        },

        -- Pattern scan - suspicious content
        pattern_scan = {
            flagged_patterns = {
                {pattern = "http[s]?://[^%s]+%s+http[s]?://", score = 30},  -- Multiple URLs
                {pattern = "(.-)%1%1%1", score = 25},  -- Repeated text
            },
        },

        -- Behavioral
        behavioral = {
            min_time_on_page_ms = 5000,  -- Humans read articles before commenting
            require_scroll = true,
        },

        -- Honeypot
        honeypot = {
            field_names = {"website_url", "comment_hp", "email2"},
        },

        -- Rate limiter
        rate_limiter = {
            requests_per_minute = 5,
            requests_per_hour = 20,
            burst_limit = 3,
        },
    },

    tags = {"wordpress", "comments", "spam", "trackback", "cms", "builtin"},
}

-- Generic Contact Form Spam Protection
local CONTACT_FORM_SPAM = {
    id = "builtin_contact_form_spam",
    name = "Contact Form Spam Protection",
    description = "Generic protection against contact form spam, applicable to any contact form endpoint",
    enabled = true,
    builtin = true,
    builtin_version = BUILTIN_VERSION,
    priority = 70,

    signatures = {
        -- Keyword filter
        keyword_filter = {
            flagged_keywords = {
                {keyword = "SEO services", score = 30},
                {keyword = "link building", score = 25},
                {keyword = "website traffic", score = 25},
                {keyword = "buy backlinks", score = 35},
                {keyword = "casino", score = 40},
                {keyword = "cryptocurrency investment", score = 30},
                {keyword = "dear sir", score = 15},  -- Common spam opener
                {keyword = "dear madam", score = 15},
                {keyword = "dear webmaster", score = 20},
            },
        },

        -- Pattern scan
        pattern_scan = {
            flagged_patterns = {
                {pattern = "http[s]?://[^%s]+", score = 10},  -- Any URL adds score
                {pattern = "http[s]?://[^%s]+%s+http[s]?://", score = 25},  -- Multiple URLs
                {pattern = "%$%d+", score = 15},  -- Money mentions
            },
        },

        -- Disposable email
        disposable_email = {
            blocked_domains = {
                "tempmail.com",
                "guerrillamail.com",
                "mailinator.com",
            },
        },

        -- Behavioral
        behavioral = {
            min_time_on_page_ms = 3000,
            require_mouse_movement = true,
        },

        -- Honeypot
        honeypot = {
            field_names = {"fax", "company_website", "url"},
        },

        -- Rate limiter
        rate_limiter = {
            requests_per_minute = 3,
            requests_per_hour = 15,
        },
    },

    tags = {"contact", "form", "spam", "generic", "builtin"},
}

-- API Abuse Protection
local API_ABUSE = {
    id = "builtin_api_abuse",
    name = "API Abuse Protection",
    description = "Protects API endpoints from automated abuse, scraping, and enumeration attacks",
    enabled = true,
    builtin = true,
    builtin_version = BUILTIN_VERSION,
    priority = 30,

    signatures = {
        -- Fingerprint
        fingerprint = {
            flagged_user_agents = {
                {pattern = "python%-requests", score = 15},
                {pattern = "Go%-http%-client", score = 15},
                {pattern = "^curl/", score = 10},
                {pattern = "PostmanRuntime", score = 5},  -- Common for testing, low score
            },
            blocked_user_agents = {
                "sqlmap",
                "nikto",
                "Nessus",
                "OpenVAS",
            },
        },

        -- Rate limiter - strict for API
        rate_limiter = {
            requests_per_second = 10,
            requests_per_minute = 100,
            requests_per_hour = 1000,
            burst_limit = 20,
        },

        -- Header consistency
        header_consistency = {
            required_headers = {"Content-Type"},
            header_rules = {
                {
                    header = "Content-Type",
                    pattern = "application/json",
                },
            },
        },
    },

    tags = {"api", "abuse", "scraping", "enumeration", "builtin"},
}

-- Credential Stuffing Protection
local CREDENTIAL_STUFFING = {
    id = "builtin_credential_stuffing",
    name = "Credential Stuffing Protection",
    description = "Generic protection against credential stuffing attacks using stolen credentials from data breaches",
    enabled = true,
    builtin = true,
    builtin_version = BUILTIN_VERSION,
    priority = 20,

    signatures = {
        -- Fingerprint - detect automation
        fingerprint = {
            blocked_user_agents = {
                "Headless",
                "PhantomJS",
                "Selenium",
                "puppeteer",
            },
            flagged_user_agents = {
                {pattern = "python%-requests", score = 20},
                {pattern = "python%-urllib", score = 20},
                {pattern = "mechanize", score = 30},
            },
        },

        -- Rate limiter - very strict for login endpoints
        rate_limiter = {
            requests_per_minute = 3,
            requests_per_hour = 20,
            burst_limit = 2,
        },

        -- Behavioral
        behavioral = {
            min_time_on_page_ms = 2000,
            require_keyboard_input = true,
        },

        -- Header consistency - expect real browser headers
        header_consistency = {
            required_headers = {"User-Agent", "Accept"},
        },
    },

    tags = {"login", "credential-stuffing", "brute-force", "authentication", "builtin"},
}

-- All builtin signatures
_M.SIGNATURES = {
    WORDPRESS_LOGIN,
    WORDPRESS_REGISTER,
    WORDPRESS_XMLRPC,
    WORDPRESS_COMMENTS,
    CONTACT_FORM_SPAM,
    API_ABUSE,
    CREDENTIAL_STUFFING,
}

-- Export individual signatures for reference
_M.WORDPRESS_LOGIN = WORDPRESS_LOGIN
_M.WORDPRESS_REGISTER = WORDPRESS_REGISTER
_M.WORDPRESS_XMLRPC = WORDPRESS_XMLRPC
_M.WORDPRESS_COMMENTS = WORDPRESS_COMMENTS
_M.CONTACT_FORM_SPAM = CONTACT_FORM_SPAM
_M.API_ABUSE = API_ABUSE
_M.CREDENTIAL_STUFFING = CREDENTIAL_STUFFING

-- Builtin version for update checking
_M.BUILTIN_VERSION = BUILTIN_VERSION

return _M
