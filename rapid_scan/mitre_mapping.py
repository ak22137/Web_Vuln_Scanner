"""Evidence-gated MITRE ATT&CK mapping.

Mappings are intentionally conservative: a severity or a keyword alone is
not evidence of an ATT&CK technique.
"""


MITRE_MAP = {}


def map_finding(finding):
    if not isinstance(finding, dict):
        return []
    explicit = finding.get("mitre_candidates")
    evidence_type = finding.get("evidence_type")
    if finding.get("finding_status") != "Confirmed" or not evidence_type:
        return []
    if explicit:
        return explicit
    finding_type = str(finding.get("finding_type", "")).lower()
    return MITRE_MAP.get(finding_type, [])
