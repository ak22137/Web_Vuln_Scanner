"""Evidence-gated MITRE ATT&CK mapping.

Mappings are intentionally conservative: a severity or a keyword alone is
not evidence of an ATT&CK technique.
"""


def map_finding(finding):
    if not isinstance(finding, dict):
        return []
    explicit = finding.get("mitre_candidates")
    evidence_type = finding.get("evidence_type")
    if explicit and evidence_type:
        return explicit
    return []
