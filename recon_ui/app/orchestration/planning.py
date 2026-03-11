from __future__ import annotations

"""Planner data structures and default deterministic plan."""

from dataclasses import dataclass


@dataclass(slots=True)
class PlannerOutput:
    """Internal planner output item consumed by deterministic scheduling logic."""

    task_type: str
    stage_name: str
    tier: str = "PASSIVE"
    approval_level: str = "NONE"
    planner_source: str = "RULE_ENGINE"
    inputs: dict | None = None


def build_default_plan(job_id: str, scope_id: str, include_active: bool = False) -> list[PlannerOutput]:
    """Return the deterministic default passive-first pipeline plan."""
    _ = (job_id, scope_id)
    plan = [
        PlannerOutput(task_type="seed_root_domain", stage_name="SEED", planner_source="RULE_ENGINE"),
        PlannerOutput(task_type="run_amass_passive", stage_name="PASSIVE_COLLECT", planner_source="RULE_ENGINE"),
        PlannerOutput(task_type="run_assetfinder_passive", stage_name="PASSIVE_COLLECT", planner_source="RULE_ENGINE"),
        PlannerOutput(task_type="run_subfinder_passive", stage_name="PASSIVE_COLLECT", planner_source="RULE_ENGINE"),
        PlannerOutput(task_type="run_crtsh_passive", stage_name="PASSIVE_COLLECT", planner_source="RULE_ENGINE"),
        PlannerOutput(task_type="run_gau_enumeration", stage_name="ENRICH", planner_source="RULE_ENGINE"),
        PlannerOutput(task_type="run_dnsx_resolution", stage_name="ENRICH", planner_source="RULE_ENGINE"),
        PlannerOutput(task_type="run_naabu_resolved", stage_name="ENRICH_POST", planner_source="RULE_ENGINE"),
        PlannerOutput(task_type="run_httpx_on_open_ports", stage_name="ENRICH_POST", planner_source="RULE_ENGINE"),
        PlannerOutput(task_type="normalize_placeholder", stage_name="NORMALIZE"),
        PlannerOutput(task_type="plan_next_placeholder", stage_name="PLAN_NEXT"),
    ]
    if include_active:
        plan.insert(
            9,
            PlannerOutput(
                task_type="run_nerva_on_open_ports",
                stage_name="ACTIVE_ENRICH",
                tier="ACTIVE",
                approval_level="HUMAN_REQUIRED",
                planner_source="RULE_ENGINE",
            ),
        )
    return plan
