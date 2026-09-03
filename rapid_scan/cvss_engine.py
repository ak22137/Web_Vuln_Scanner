"""Small, dependency-free CVSS v3.1 base-score calculator.

The scanner only applies a score when a finding supplies a complete CVSS
vector.  It never invents a vector from a severity label.
"""

import math


def _roundup(value):
    return math.ceil(value * 10 - 1e-10) / 10


def calculate_base_score(vector):
    if not isinstance(vector, str) or not vector.startswith("CVSS:3.1/"):
        raise ValueError("a CVSS:3.1 vector is required")
    metrics = {}
    for component in vector.split("/")[1:]:
        key, separator, value = component.partition(":")
        if not separator or key in metrics:
            raise ValueError("invalid CVSS vector component")
        metrics[key] = value
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if set(metrics) != required:
        raise ValueError("complete CVSS v3.1 base metrics are required")
    av = {"N": .85, "A": .62, "L": .55, "P": .2}[metrics["AV"]]
    ac = {"L": .77, "H": .44}[metrics["AC"]]
    ui = {"N": .85, "R": .62}[metrics["UI"]]
    scope_changed = metrics["S"] == "C"
    pr = ({"N": .85, "L": .68, "H": .50} if scope_changed
          else {"N": .85, "L": .62, "H": .27})[metrics["PR"]]
    confidentiality = {"N": 0, "L": .22, "H": .56}[metrics["C"]]
    integrity = {"N": 0, "L": .22, "H": .56}[metrics["I"]]
    availability = {"N": 0, "L": .22, "H": .56}[metrics["A"]]
    impact_subscore = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    if impact_subscore <= 0:
        return 0.0
    if scope_changed:
        impact = 7.52 * (impact_subscore - .029) - 3.25 * (impact_subscore - .02) ** 15
    else:
        impact = 6.42 * impact_subscore
    exploitability = 8.22 * av * ac * pr * ui
    score = min(1.08 * (impact + exploitability), 10) if scope_changed else min(impact + exploitability, 10)
    return _roundup(score)


def vector_from_facts(facts):
    """Build a CVSS base vector only from complete verified impact facts."""
    if not isinstance(facts, dict):
        return None
    names = {"AV": "attack_vector", "AC": "attack_complexity", "PR": "privileges_required",
             "UI": "user_interaction", "S": "scope", "C": "confidentiality",
             "I": "integrity", "A": "availability"}
    values = {key: facts.get(name) for key, name in names.items()}
    if any(value not in {
        "AV": {"N", "A", "L", "P"}, "AC": {"L", "H"},
        "PR": {"N", "L", "H"}, "UI": {"N", "R"}, "S": {"U", "C"},
        "C": {"N", "L", "H"}, "I": {"N", "L", "H"}, "A": {"N", "L", "H"}
    }[key] for key, value in values.items()):
        return None
    return "CVSS:3.1/" + "/".join(f"{key}:{values[key]}" for key in names)
