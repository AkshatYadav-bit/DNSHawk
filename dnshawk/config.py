"""
DNSHawk detection configuration.

Thresholds defined here are initial experimental values.
They must be validated and tuned using controlled DNS traffic.
"""


# ---------------------------------------------------------
# Rule-based DNS tunneling detection
# ---------------------------------------------------------

RULE_THRESHOLDS = {

    # Maximum subdomain length observed in a window.
    "max_subdomain_length": 50,

    # Average Shannon entropy of subdomains.
    "avg_subdomain_entropy": 3.5,

    # DNS queries per second within the window.
    "queries_per_second": 1.0,

    # Ratio of unique subdomains to non-empty
    # subdomain observations.
    "unique_subdomain_ratio": 0.8,

    # Ratio of NXDOMAIN responses.
    "nxdomain_rate": 0.3,

    
}


# ---------------------------------------------------------
# Rule weights
# ---------------------------------------------------------

RULE_WEIGHTS = {

    "long_subdomain": 1.0,

    "high_subdomain_entropy": 1.0,

    "high_query_rate": 1.0,

    "high_unique_subdomain_ratio": 1.0,

    "high_nxdomain_rate": 1.0,
}

# ---------------------------------------------------------
# Minimum evidence requirements
# ---------------------------------------------------------

MINIMUM_QUERY_COUNT = 10