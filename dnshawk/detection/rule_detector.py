from dnshawk.config import (
    RULE_THRESHOLDS,
    RULE_WEIGHTS,
    MINIMUM_QUERY_COUNT,
)


class RuleDetector:
    """
    Rule-based DNS tunneling detector.

    This class evaluates individual behavioral indicators
    produced by FeatureEngine.

    It does not make a final classification yet.
    """

    def __init__(
        self,
        thresholds=None,
        weights=None
    ):
        self.thresholds = (
            thresholds
            if thresholds is not None
            else RULE_THRESHOLDS
        )

        self.weights = (
            weights
            if weights is not None
            else RULE_WEIGHTS
        )

    # ---------------------------------------------------------
    # Public interface
    # ---------------------------------------------------------

    def evaluate(self, features):
        """
        Evaluate all configured DNS tunneling rules.

        Args:
            features (dict):
                FeatureEngine output.

        Returns:
            dict:
                Individual rule results.
        """

        return {
            "long_subdomain":
                self.check_long_subdomain(features),

            "high_subdomain_entropy":
                self.check_high_subdomain_entropy(features),

            "high_query_rate":
                self.check_high_query_rate(features),

            "high_unique_subdomain_ratio":
                self.check_high_unique_subdomain_ratio(features),

            "high_nxdomain_rate":
                self.check_high_nxdomain_rate(features),
        }

    # ---------------------------------------------------------
    # Rule 1: Long subdomain
    # ---------------------------------------------------------

    def check_long_subdomain(self, features):

        value = features.get(
            "max_subdomain_length",
            0.0
        )

        threshold = self.thresholds[
            "max_subdomain_length"
        ]

        triggered = value >= threshold

        return {
            "triggered": triggered,
            "value": value,
            "threshold": threshold,
            "weight": self.weights[
                "long_subdomain"
            ],
            "reason": (
                "Maximum subdomain length "
                "exceeded threshold."
                if triggered
                else
                "Maximum subdomain length "
                "is below threshold."
            )
        }

    # ---------------------------------------------------------
    # Rule 2: High subdomain entropy
    # ---------------------------------------------------------

    def check_high_subdomain_entropy(self, features):

        value = features.get(
            "avg_subdomain_entropy",
            0.0
        )

        threshold = self.thresholds[
            "avg_subdomain_entropy"
        ]

        triggered = value >= threshold

        return {
            "triggered": triggered,
            "value": value,
            "threshold": threshold,
            "weight": self.weights[
                "high_subdomain_entropy"
            ],
            "reason": (
                "Average subdomain entropy "
                "exceeded threshold."
                if triggered
                else
                "Average subdomain entropy "
                "is below threshold."
            )
        }

    # ---------------------------------------------------------
    # Rule 3: High query rate
    # ---------------------------------------------------------

    def check_high_query_rate(self, features):

        value = features.get(
            "queries_per_second",
            0.0
        )

        threshold = self.thresholds[
            "queries_per_second"
        ]

        triggered = value >= threshold

        return {
            "triggered": triggered,
            "value": value,
            "threshold": threshold,
            "weight": self.weights[
                "high_query_rate"
            ],
            "reason": (
                "DNS query rate "
                "exceeded threshold."
                if triggered
                else
                "DNS query rate "
                "is below threshold."
            )
        }

    # ---------------------------------------------------------
    # Rule 4: High unique-subdomain ratio
    # ---------------------------------------------------------

    def check_high_unique_subdomain_ratio(
        self,
        features
    ):

        value = features.get(
            "unique_subdomain_ratio",
            0.0
        )

        threshold = self.thresholds[
            "unique_subdomain_ratio"
        ]

        triggered = value >= threshold

        return {
            "triggered": triggered,
            "value": value,
            "threshold": threshold,
            "weight": self.weights[
                "high_unique_subdomain_ratio"
            ],
            "reason": (
                "Unique subdomain ratio "
                "exceeded threshold."
                if triggered
                else
                "Unique subdomain ratio "
                "is below threshold."
            )
        }

    # ---------------------------------------------------------
    # Rule 5: High NXDOMAIN rate
    # ---------------------------------------------------------

    def check_high_nxdomain_rate(
        self,
        features
    ):

        value = features.get(
            "nxdomain_rate",
            0.0
        )

        threshold = self.thresholds[
            "nxdomain_rate"
        ]

        triggered = value >= threshold

        return {
            "triggered": triggered,
            "value": value,
            "threshold": threshold,
            "weight": self.weights[
                "high_nxdomain_rate"
            ],
            "reason": (
                "NXDOMAIN rate "
                "exceeded threshold."
                if triggered
                else
                "NXDOMAIN rate "
                "is below threshold."
            )
        }

        # ---------------------------------------------------------
    # Evidence aggregation
    # ---------------------------------------------------------

    def assess(self, features):
        """
        Aggregate individual rule results into a weighted
        evidence score.

        Minimum query count is applied before rule results
        are allowed to contribute to the score.

        Returns:
            dict containing:
                - minimum_evidence_met
                - query_count
                - triggered_rules
                - score
                - max_score
                - normalized_score
                - rule_results
        """

        query_count = features.get(
            "query_count",
            0
        )

        rule_results = self.evaluate(
            features
        )

        minimum_evidence_met = (
            query_count
            >= MINIMUM_QUERY_COUNT
        )

        triggered_rules = []

        score = 0.0

        max_score = sum(
            self.weights.values()
        )

        # -----------------------------------------------------
        # Only allow rules to contribute when there is enough
        # traffic in the window.
        # -----------------------------------------------------

        if minimum_evidence_met:

            for rule_name, result in rule_results.items():

                if result["triggered"]:

                    triggered_rules.append(
                        rule_name
                    )

                    score += result["weight"]

        normalized_score = (
            score / max_score
            if max_score > 0
            else 0.0
        )

        return {
            "minimum_evidence_met":
                minimum_evidence_met,

            "query_count":
                query_count,

            "triggered_rules":
                triggered_rules,

            "score":
                score,

            "max_score":
                max_score,

            "normalized_score":
                normalized_score,

            "rule_results":
                rule_results,
        }