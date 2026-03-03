"""MITRE ATT&CK integration for Tracecat.

Look up a MITRE ATT&CK technique or tactic by ID to get its name,
description, and URL.  Fetches the full STIX bundle from GitHub and
filters locally (the TAXII 2.0 server is rate-limited to 10 req / 10 min).
"""

from __future__ import annotations

from typing import Annotated

import requests
from pydantic import Field
from tracecat_registry import registry

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def _fetch_stix_objects() -> list[dict]:
    """Download the MITRE ATT&CK Enterprise STIX bundle and return its objects."""
    response = requests.get(STIX_URL, timeout=90)
    response.raise_for_status()
    return response.json().get("objects", [])


def _build_lookups(
    objects: list[dict],
) -> tuple[dict, dict, dict]:
    """Single pass over STIX objects to build tactic, technique, and slug maps.

    Returns
    -------
    tactic_map
        Keyed by tactic external ID (e.g. ``TA0001``).
    technique_map
        Keyed by technique external ID (e.g. ``T1059``).
    tactic_slug_to_id
        Maps slugified phase names (e.g. ``initial-access``) to tactic external IDs.
    """
    tactic_map: dict[str, dict] = {}
    technique_map: dict[str, dict] = {}
    tactic_slug_to_id: dict[str, str] = {}

    # --- First pass: collect tactics so we can resolve slugs ---------------
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        ext_refs = obj.get("external_references", [{}])
        tactic_id = ext_refs[0].get("external_id")
        tactic_name = obj.get("name")
        if not tactic_id or not tactic_name:
            continue

        slug = tactic_name.lower().replace(" ", "-")
        tactic_slug_to_id[slug] = tactic_id
        tactic_map[tactic_id] = {
            "tactic_id": tactic_id,
            "tactic_name": tactic_name,
            "description": obj.get("description", ""),
            "url": ext_refs[0].get("url", f"https://attack.mitre.org/tactics/{tactic_id}"),
            "techniques": [],
        }

    # --- Second pass: collect techniques -----------------------------------
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue

        external_refs = obj.get("external_references", [])
        technique_id = None
        url = None
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url = ref.get("url")
                break
        if not technique_id:
            continue

        # Resolve tactics via kill_chain_phases
        tactics: list[dict] = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            tid = tactic_slug_to_id.get(phase.get("phase_name", ""))
            if tid and tid in tactic_map:
                tactics.append({
                    "tactic_id": tid,
                    "tactic_name": tactic_map[tid]["tactic_name"],
                })

        is_subtechnique = "." in technique_id
        parent_technique_id = technique_id.split(".")[0] if is_subtechnique else None

        tech_entry = {
            "technique_id": technique_id,
            "technique_name": obj.get("name"),
            "description": obj.get("description", ""),
            "url": url or f"https://attack.mitre.org/techniques/{technique_id}",
            "is_subtechnique": is_subtechnique,
            "parent_technique_id": parent_technique_id,
            "platforms": obj.get("x_mitre_platforms", []),
            "tactics": tactics,
        }
        technique_map[technique_id] = tech_entry

        # Register this technique under each of its tactics (lightweight)
        for tac in tactics:
            tid = tac["tactic_id"]
            if tid in tactic_map:
                tactic_map[tid]["techniques"].append({
                    "technique_id": technique_id,
                    "technique_name": obj.get("name"),
                })

    return tactic_map, technique_map, tactic_slug_to_id


@registry.register(
    default_title="Lookup MITRE ATT&CK",
    description="Look up a MITRE ATT&CK technique or tactic by ID to get its name, description, and URL",
    display_group="MITRE",
    namespace="integrations.mitre",
)
def lookup_attack(
    technique_id: Annotated[
        str | None,
        Field(description="Technique ID, e.g. T1059 or T1059.001"),
    ] = None,
    tactic_id: Annotated[
        str | None,
        Field(description="Tactic ID, e.g. TA0001"),
    ] = None,
) -> dict:
    """Look up a MITRE ATT&CK technique or tactic by ID.

    At least one of ``technique_id`` or ``tactic_id`` must be provided.
    If both are given the result contains ``technique`` and ``tactic`` keys.

    Note: technique lookups already include parent tactic info in the
    ``tactics`` list, so standalone tactic lookup may not be needed for
    most enrichment use cases.
    """
    if not technique_id and not tactic_id:
        raise ValueError("At least one of technique_id or tactic_id must be provided")

    objects = _fetch_stix_objects()
    tactic_map, technique_map, _ = _build_lookups(objects)

    result: dict = {}

    if technique_id:
        technique_id = technique_id.strip().strip('"').upper()
        tech = technique_map.get(technique_id)
        if not tech:
            raise ValueError(f"Technique {technique_id!r} not found in MITRE ATT&CK Enterprise")
        if tactic_id:
            result["technique"] = tech
        else:
            result = tech

    if tactic_id:
        tactic_id = tactic_id.strip().strip('"').upper()
        tac = tactic_map.get(tactic_id)
        if not tac:
            raise ValueError(f"Tactic {tactic_id!r} not found in MITRE ATT&CK Enterprise")
        tac_result = {
            "tactic_id": tac["tactic_id"],
            "tactic_name": tac["tactic_name"],
            "description": tac["description"],
            "url": tac["url"],
            "technique_count": len(tac["techniques"]),
            "techniques": tac["techniques"],
        }
        if technique_id:
            result["tactic"] = tac_result
        else:
            result = tac_result

    return result
