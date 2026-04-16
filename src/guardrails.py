"""
Context-Aware Guardrails - A-CODE Security Protocol
Author: Elshan Aliev
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from enum import Enum


class Role(Enum):
    USER = "user"
    ADMIN = "admin"
    AUDITOR = "auditor"
    DEVELOPER = "developer"
    GUEST = "guest"


class Action(Enum):
    READ_LOGS = "read_logs"
    EDIT_PROMPTS = "edit_prompts"
    RUN_INFERENCE = "run_inference"
    ACCESS_SENSITIVE = "access_sensitive"
    EXPORT_DATA = "export_data"


@dataclass
class Policy:
    role: Role
    allowed_actions: List[Action]


class ContextGuardrails:
    POLICIES = {
        Role.GUEST: Policy(Role.GUEST, []),
        Role.USER: Policy(Role.USER, [Action.RUN_INFERENCE]),
        Role.DEVELOPER: Policy(Role.DEVELOPER, [Action.RUN_INFERENCE, Action.READ_LOGS, Action.EDIT_PROMPTS]),
        Role.ADMIN: Policy(Role.ADMIN, [Action.RUN_INFERENCE, Action.READ_LOGS, Action.EDIT_PROMPTS, Action.EXPORT_DATA]),
        Role.AUDITOR: Policy(Role.AUDITOR, [Action.READ_LOGS, Action.EXPORT_DATA]),
    }
    
    def check(self, prompt: str, context: Dict, requested_action: Action) -> Tuple[bool, str]:
        role_str = context.get("role", "user").lower()
        role_map = {
            "admin": Role.ADMIN,
            "auditor": Role.AUDITOR,
            "developer": Role.DEVELOPER,
            "guest": Role.GUEST,
        }
        role = role_map.get(role_str, Role.USER)
        policy = self.POLICIES.get(role)
        
        if requested_action not in policy.allowed_actions:
            return False, f"[DENIED] Role '{role.value}' cannot perform '{requested_action.value}'"
        return True, f"[ALLOWED] Role '{role.value}' can perform '{requested_action.value}'"


if __name__ == "__main__":
    g = ContextGuardrails()
    result, msg = g.check("test", {"role": "admin"}, Action.READ_LOGS)
    print(msg)
