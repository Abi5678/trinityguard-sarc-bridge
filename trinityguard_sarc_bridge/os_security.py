"""
OS Security Layer — Structural Security for TrinityGuard-SARC Bridge.

Implements OS-like security mechanisms for LLM agent systems, as proposed
in arXiv:2605.14932 "Toward Securing AI Agents Like Operating Systems":

  1. Process Isolation — Isolation domains for agent sessions
  2. Privilege Separation — Capability tokens for tool access control
  3. Communication Mediation — IPC policy enforcement for inter-agent messages
  4. Action Chain Analysis — Cross-action composition detection

All enforcement routes through SARC's existing 4 enforcement sites
(PRE_ACTION, ACTION_TIME, POST_ACTION, PERIODIC). Components are
opt-in and backward-compatible with existing bridge behavior.

Reference: arXiv:2605.14932 (TU Berlin / RUB, 2026)
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from .bridge import AgentAction, Decision


# ---------------------------------------------------------------------------
# 1. Process Isolation — IsolationDomain
# ---------------------------------------------------------------------------

class DomainType(str, Enum):
    """Types of isolation domains."""
    USER = "user"              # User-initiated session
    AGENT = "agent"            # Single agent session
    SUBAGENT = "subagent"      # Subagent (child of another agent)
    SANDBOX = "sandbox"        # Sandboxed execution
    EXTERNAL = "external"      # External data source (web, email, etc.)


@dataclass(frozen=True)
class DomainPolicy:
    """Policy for an isolation domain."""
    domain_type: DomainType
    allowed_paths: frozenset[str] = frozenset()          # Allowed file paths
    denied_paths: frozenset[str] = frozenset()           # Denied file paths
    allowed_tools: frozenset[str] = frozenset()          # Allowed tool names
    denied_tools: frozenset[str] = frozenset()           # Denied tool names
    allowed_recipients: frozenset[str] = frozenset()     # Allowed message targets
    max_actions_per_minute: int = 120                     # Rate limit
    can_spawn_subagents: bool = True                      # Subagent creation
    parent_domain: str | None = None                      # Parent domain ID
    inherit_capabilities: bool = True                     # Inherit from parent


# Default domain policies by type
_DEFAULT_POLICIES: dict[DomainType, DomainPolicy] = {
    DomainType.USER: DomainPolicy(
        domain_type=DomainType.USER,
        allowed_paths=frozenset({"/"}),
        allowed_tools=frozenset({"*"}),  # All tools
        allowed_recipients=frozenset({"*"}),
        can_spawn_subagents=True,
    ),
    DomainType.AGENT: DomainPolicy(
        domain_type=DomainType.AGENT,
        denied_paths=frozenset({
            "/etc/", "/proc/", "/sys/", "/dev/",
            ".ssh/", ".env", ".gnupg/",
        }),
        denied_tools=frozenset({"exec:elevated"}),
        can_spawn_subagents=True,
    ),
    DomainType.SUBAGENT: DomainPolicy(
        domain_type=DomainType.SUBAGENT,
        denied_paths=frozenset({
            "/etc/", "/proc/", "/sys/", "/dev/",
            ".ssh/", ".env", ".gnupg/",
            "MEMORY.md", "USER.md",
        }),
        denied_tools=frozenset({"exec:elevated", "message:send"}),
        allowed_recipients=frozenset(),  # No external messaging
        inherit_capabilities=True,
    ),
    DomainType.SANDBOX: DomainPolicy(
        domain_type=DomainType.SANDBOX,
        allowed_paths=frozenset({"/tmp/"}),
        allowed_tools=frozenset({"read", "write", "exec"}),
        allowed_recipients=frozenset(),
        can_spawn_subagents=False,
    ),
    DomainType.EXTERNAL: DomainPolicy(
        domain_type=DomainType.EXTERNAL,
        allowed_paths=frozenset(),
        allowed_tools=frozenset(),
        allowed_recipients=frozenset(),
        can_spawn_subagents=False,
    ),
}


@dataclass
class IsolationDomain:
    """An isolation domain for an agent session.

    Provides structural isolation between agents, preventing privilege
    escalation and cross-domain contamination (arXiv:2605.14932 §III.A).
    """
    domain_id: str
    domain_type: DomainType
    policy: DomainPolicy
    created_at: float = field(default_factory=time.time)
    action_count: int = 0
    last_action_time: float = 0.0
    parent_domain: str | None = None
    children: list[str] = field(default_factory=list)  # Child domain IDs
    metadata: dict[str, Any] = field(default_factory=dict)

    def check_action(self, action: AgentAction) -> tuple[bool, str]:
        """Check if an action is allowed within this domain.

        Returns (allowed, reason).
        """
        self.action_count += 1
        self.last_action_time = time.time()

        # Check tool access
        tool_name = action.action
        if self.policy.allowed_tools and "*" not in self.policy.allowed_tools:
            if tool_name not in self.policy.allowed_tools:
                if not any(tool_name.startswith(d) for d in self.policy.denied_tools):
                    return False, f"Tool '{tool_name}' not in domain's allowed tools"

        if any(tool_name.startswith(d) for d in self.policy.denied_tools):
            return False, f"Tool '{tool_name}' explicitly denied in domain policy"

        # Check file path access
        params = action.params or {}
        for path_key in ("path", "source", "target", "dest", "file_path"):
            path_val = params.get(path_key, "")
            if isinstance(path_val, str) and path_val:
                if self._is_path_denied(path_val):
                    return False, f"Path '{path_val}' denied by domain policy"
                if self.policy.allowed_paths and "*" not in self.policy.allowed_paths:
                    if not any(path_val.startswith(p) for p in self.policy.allowed_paths):
                        return False, f"Path '{path_val}' not in domain's allowed paths"

        # Check rate limit
        if self.action_count > self.policy.max_actions_per_minute:
            elapsed = time.time() - self.created_at
            rate = self.action_count / max(elapsed, 1.0) * 60
            if rate > self.policy.max_actions_per_minute:
                return False, f"Rate limit exceeded: {rate:.1f}/min > {self.policy.max_actions_per_minute}/min"

        return True, ""

    def check_message_recipient(self, target: str) -> tuple[bool, str]:
        """Check if a message can be sent to the given target."""
        if not self.policy.allowed_recipients:
            return False, "Domain does not allow external messaging"
        if "*" not in self.policy.allowed_recipients:
            if target not in self.policy.allowed_recipients:
                return False, f"Recipient '{target}' not in domain's allowed recipients"
        return True, ""

    def _is_path_denied(self, path: str) -> bool:
        """Check if a path matches any denied path pattern."""
        # Normalize path
        path = path.replace("//", "/").rstrip("/")

        # Direct prefix match
        for denied in self.policy.denied_paths:
            if path.startswith(denied) or denied.startswith(path):
                return True

        # Pattern matching for glob-like patterns
        for denied in self.policy.denied_paths:
            pattern = denied.replace("*", ".*").replace("?", ".")
            if re.match(pattern, path):
                return True

        return False

    def check_can_spawn(self) -> tuple[bool, str]:
        """Check if this domain can spawn child domains."""
        if not self.policy.can_spawn_subagents:
            return False, "Domain policy prohibits spawning subagents"
        return True, ""


class IsolationDomainManager:
    """Manages isolation domains for agent sessions.

    Creates, tracks, and enforces isolation boundaries between agents.
    Implements the process isolation mechanism from arXiv:2605.14932 §III.A.
    """

    def __init__(self) -> None:
        self._domains: dict[str, IsolationDomain] = {}
        self._domain_counter: int = 0

    def create_domain(
        self,
        domain_type: DomainType,
        policy_override: DomainPolicy | None = None,
        parent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IsolationDomain:
        """Create a new isolation domain."""
        self._domain_counter += 1
        domain_id = f"dom_{domain_type.value}_{self._domain_counter}"

        if policy_override:
            policy = policy_override
        elif parent_id and parent_id in self._domains:
            parent = self._domains[parent_id]
            base = _DEFAULT_POLICIES.get(domain_type, _DEFAULT_POLICIES[DomainType.AGENT])
            # Child domains inherit denied paths from parent
            if parent.policy.inherit_capabilities:
                merged_denied = parent.policy.denied_paths | base.denied_paths
                policy = DomainPolicy(
                    domain_type=base.domain_type,
                    allowed_paths=base.allowed_paths,
                    denied_paths=merged_denied,
                    allowed_tools=base.allowed_tools - parent.policy.denied_tools,
                    denied_tools=base.denied_tools | parent.policy.denied_tools,
                    allowed_recipients=base.allowed_recipients,
                    max_actions_per_minute=base.max_actions_per_minute,
                    can_spawn_subagents=base.can_spawn_subagents,
                    parent_domain=parent_id,
                    inherit_capabilities=base.inherit_capabilities,
                )
            else:
                policy = base
        else:
            policy = _DEFAULT_POLICIES.get(domain_type, _DEFAULT_POLICIES[DomainType.AGENT])

        domain = IsolationDomain(
            domain_id=domain_id,
            domain_type=domain_type,
            policy=policy,
            metadata=metadata or {},
        )
        domain.parent_domain = parent_id

        self._domains[domain_id] = domain

        if parent_id and parent_id in self._domains:
            self._domains[parent_id].children.append(domain_id)

        return domain

    def get_domain(self, domain_id: str) -> IsolationDomain | None:
        """Get a domain by ID."""
        return self._domains.get(domain_id)

    def check_action(self, domain_id: str, action: AgentAction) -> tuple[bool, str]:
        """Check if an action is allowed in the given domain."""
        domain = self._domains.get(domain_id)
        if not domain:
            return False, f"Domain '{domain_id}' not found"
        return domain.check_action(action)

    def check_cross_domain_access(
        self, source_domain_id: str, target_domain_id: str
    ) -> tuple[bool, str]:
        """Check if one domain can access another's resources."""
        source = self._domains.get(source_domain_id)
        target = self._domains.get(target_domain_id)
        if not source or not target:
            return False, "Domain not found"

        # Parent domains can access children
        if target.parent_domain == source_domain_id:
            return True, ""

        # Children cannot access parent (prevents privilege escalation)
        if source.parent_domain == target_domain_id:
            return False, "Child domain cannot access parent domain"

        # Sibling domains cannot access each other (isolation)
        if source.parent_domain and source.parent_domain == target.parent_domain:
            return False, "Sibling domains are isolated from each other"

        # Default: deny cross-domain access
        return False, f"Cross-domain access from '{source_domain_id}' to '{target_domain_id}' denied"

    def destroy_domain(self, domain_id: str) -> bool:
        """Destroy a domain and all its children."""
        domain = self._domains.get(domain_id)
        if not domain:
            return False

        # Destroy children first (recursive)
        for child_id in list(domain.children):
            self.destroy_domain(child_id)

        del self._domains[domain_id]

        # Remove from parent's children list
        if domain.parent_domain and domain.parent_domain in self._domains:
            parent = self._domains[domain.parent_domain]
            if domain_id in parent.children:
                parent.children.remove(domain_id)

        return True

    def all_domains(self) -> list[IsolationDomain]:
        """Return all active domains."""
        return list(self._domains.values())


# ---------------------------------------------------------------------------
# 2. Privilege Separation — Capability Tokens
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CapabilityToken:
    """A capability token granting specific tool access.

    Implements capability-based security (arXiv:2605.14932 §III.B).
    Each token grants access to specific tools with constraints.
    """
    token_id: str
    tool_pattern: str           # Tool name or pattern (e.g., "exec", "file_*")
    granted_by: str             # Who granted this token
    granted_to: str             # Agent/domain receiving the token
    max_uses: int | None = None  # Max invocations (None = unlimited)
    expires_at: float | None = None  # Expiration timestamp
    params_constraint: dict[str, Any] = field(default_factory=dict)  # Parameter constraints
    created_at: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def matches_tool(self, tool_name: str) -> bool:
        if self.tool_pattern == "*":
            return True
        if self.tool_pattern == tool_name:
            return True
        # Support wildcard patterns (e.g., "file_*")
        pattern = self.tool_pattern.replace("*", ".*")
        return bool(re.match(f"^{pattern}$", tool_name))

    def check_params(self, params: dict[str, Any]) -> tuple[bool, str]:
        """Check if action parameters satisfy token constraints."""
        for key, constraint in self.params_constraint.items():
            value = params.get(key)
            if constraint.get("required") and value is None:
                return False, f"Required parameter '{key}' missing"
            if "allowed_values" in constraint and value is not None:
                if value not in constraint["allowed_values"]:
                    return False, f"Parameter '{key}' value '{value}' not in allowed values"
            if "max_length" in constraint and isinstance(value, str):
                if len(value) > constraint["max_length"]:
                    return False, f"Parameter '{key}' exceeds max length"
            if "pattern" in constraint and isinstance(value, str):
                if not re.match(constraint["pattern"], value):
                    return False, f"Parameter '{key}' doesn't match required pattern"
        return True, ""


class CapabilityManager:
    """Manages capability tokens for tool access control.

    Implements privilege separation (arXiv:2605.14932 §III.B).
    Agents must possess matching capability tokens to invoke tools.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, CapabilityToken] = {}
        self._agent_tokens: dict[str, list[str]] = defaultdict(list)  # agent_id -> [token_ids]
        self._use_counts: dict[str, int] = defaultdict(int)
        self._revoked: set[str] = set()
        self._token_counter: int = 0

    def grant_token(
        self,
        tool_pattern: str,
        granted_by: str,
        granted_to: str,
        max_uses: int | None = None,
        ttl_seconds: float | None = None,
        params_constraint: dict[str, Any] | None = None,
    ) -> CapabilityToken:
        """Grant a new capability token."""
        self._token_counter += 1
        token_id = f"cap_{self._token_counter:04d}"

        expires_at = None
        if ttl_seconds:
            expires_at = time.time() + ttl_seconds

        token = CapabilityToken(
            token_id=token_id,
            tool_pattern=tool_pattern,
            granted_by=granted_by,
            granted_to=granted_to,
            max_uses=max_uses,
            expires_at=expires_at,
            params_constraint=params_constraint or {},
        )

        self._tokens[token_id] = token
        self._agent_tokens[granted_to].append(token_id)

        return token

    def revoke_token(self, token_id: str) -> bool:
        """Revoke a capability token."""
        if token_id in self._tokens:
            self._revoked.add(token_id)
            return True
        return False

    def check_tool_access(
        self,
        agent_id: str,
        tool_name: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """Check if an agent has capability to use a tool.

        Returns (allowed, reason).
        """
        params = params or {}
        token_ids = self._agent_tokens.get(agent_id, [])

        matching_tokens = []
        for tid in token_ids:
            if tid in self._revoked:
                continue
            token = self._tokens.get(tid)
            if not token:
                continue
            if token.is_expired():
                self._revoked.add(tid)
                continue
            if token.matches_tool(tool_name):
                matching_tokens.append(token)

        if not matching_tokens:
            return False, f"Agent '{agent_id}' has no capability token for tool '{tool_name}'"

        # Check the most specific token (longest pattern match)
        matching_tokens.sort(key=lambda t: len(t.tool_pattern), reverse=True)
        token = matching_tokens[0]

        # Check usage limit
        if token.max_uses is not None:
            uses = self._use_counts[token.token_id]
            if uses >= token.max_uses:
                self._revoked.add(token.token_id)
                return False, f"Capability token '{token.token_id}' exhausted ({token.max_uses} uses)"

        # Check parameter constraints
        params_ok, reason = token.check_params(params)
        if not params_ok:
            return False, reason

        # Increment use count
        self._use_counts[token.token_id] += 1

        return True, ""

    def get_agent_tokens(self, agent_id: str) -> list[CapabilityToken]:
        """Get all active tokens for an agent."""
        tokens = []
        for tid in self._agent_tokens.get(agent_id, []):
            if tid in self._revoked:
                continue
            token = self._tokens.get(tid)
            if token and not token.is_expired():
                tokens.append(token)
        return tokens

    def revoke_all_for_agent(self, agent_id: str) -> int:
        """Revoke all tokens for an agent. Returns count revoked."""
        count = 0
        for tid in self._agent_tokens.get(agent_id, []):
            if tid not in self._revoked:
                self._revoked.add(tid)
                count += 1
        return count


# ---------------------------------------------------------------------------
# 3. Communication Mediation — IPC Mediator
# ---------------------------------------------------------------------------

class MessageDirection(str, Enum):
    """Direction of inter-agent message."""
    OUTBOUND = "outbound"    # From agent to external
    INBOUND = "inbound"      # From external to agent
    INTERNAL = "internal"    # Between agents in same domain


@dataclass
class IPCPolicy:
    """Policy for inter-agent communication."""
    allowed_directions: frozenset[MessageDirection] = frozenset({MessageDirection.INTERNAL})
    allowed_recipients: frozenset[str] = frozenset()
    denied_recipients: frozenset[str] = frozenset()
    max_message_rate: int = 60       # Messages per minute
    max_message_size: int = 10000    # Characters
    content_filter_patterns: list[str] = field(default_factory=list)
    require_authentication: bool = True
    log_all_messages: bool = True


class IPCMediator:
    """Mediates inter-agent communication.

    Implements communication mediation (arXiv:2605.14932 §III.C).
    All inter-agent messages pass through this mediator, which enforces
    policies on content, recipients, and frequency.
    """

    def __init__(self) -> None:
        self._policies: dict[str, IPCPolicy] = {}  # agent_id -> policy
        self._message_log: list[dict[str, Any]] = []
        self._rate_counters: dict[str, list[float]] = defaultdict(list)
        self._blocked_domains: set[str] = set()
        self._content_filters: list[re.Pattern] = []

    def set_policy(self, agent_id: str, policy: IPCPolicy) -> None:
        """Set IPC policy for an agent."""
        self._policies[agent_id] = policy
        # Compile content filter patterns
        self._content_filters = [
            re.compile(p, re.IGNORECASE)
            for p in policy.content_filter_patterns
        ]

    def mediate(
        self,
        sender_id: str,
        recipient_id: str,
        content: str,
        direction: MessageDirection = MessageDirection.INTERNAL,
    ) -> tuple[bool, str]:
        """Mediate a message between agents.

        Returns (allowed, reason).
        """
        policy = self._policies.get(sender_id)
        if not policy:
            return False, f"No IPC policy for sender '{sender_id}'"

        # Check direction
        if direction not in policy.allowed_directions:
            return False, f"Message direction '{direction.value}' not allowed for '{sender_id}'"

        # Check recipient
        if recipient_id in policy.denied_recipients:
            return False, f"Recipient '{recipient_id}' is in denied list"
        if (policy.allowed_recipients and
                "*" not in policy.allowed_recipients and
                recipient_id not in policy.allowed_recipients):
            return False, f"Recipient '{recipient_id}' not in allowed list"

        # Check rate limit
        now = time.time()
        self._rate_counters[sender_id].append(now)
        # Clean old entries (older than 60 seconds)
        cutoff = now - 60.0
        self._rate_counters[sender_id] = [
            t for t in self._rate_counters[sender_id] if t > cutoff
        ]
        if len(self._rate_counters[sender_id]) > policy.max_message_rate:
            return False, f"Message rate limit exceeded for '{sender_id}'"

        # Check message size
        if len(content) > policy.max_message_size:
            return False, f"Message size {len(content)} exceeds limit {policy.max_message_size}"

        # Content filter
        for pattern in self._content_filters:
            if pattern.search(content):
                return False, f"Message content matches blocked pattern: {pattern.pattern}"

        # Log the message
        if policy.log_all_messages:
            self._message_log.append({
                "sender": sender_id,
                "recipient": recipient_id,
                "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
                "direction": direction.value,
                "timestamp": now,
                "length": len(content),
            })

        return True, ""

    def check_inbound(self, sender_id: str, content: str) -> tuple[bool, str]:
        """Check an inbound message for injection patterns.

        Detects potential prompt injection in messages from external sources.
        """
        injection_patterns = [
            r"ignore\s+(all\s+)?previous\s+(instructions|prompts)",
            r"you\s+are\s+now\s+a",
            r"new\s+instruction[s]?:",
            r"system\s*:\s*",
            r"override\s+safety",
            r"<\|im_start\|>",
            r"\[INST\]",
            r"<<SYS>>",
        ]

        for pattern in injection_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return False, f"Inbound message contains potential injection pattern: {pattern}"

        return True, ""

    def block_domain(self, domain_id: str) -> None:
        """Block all communication from a domain."""
        self._blocked_domains.add(domain_id)

    def unblock_domain(self, domain_id: str) -> None:
        """Unblock a domain."""
        self._blocked_domains.discard(domain_id)

    def get_message_log(
        self,
        sender_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get message log, optionally filtered by sender."""
        logs = self._message_log
        if sender_id:
            logs = [l for l in logs if l["sender"] == sender_id]
        return logs[-limit:]


# ---------------------------------------------------------------------------
# 4. Action Chain Analyzer — Composition Detection
# ---------------------------------------------------------------------------

@dataclass
class ChainStep:
    """A step in an action chain."""
    action: str
    params: dict[str, Any]
    timestamp: float
    domain_id: str
    agent_id: str
    result_summary: str = ""  # Brief summary of the action result


@dataclass
class ChainAlert:
    """Alert from the chain analyzer."""
    alert_type: str        # e.g., "privilege_escalation", "data_exfiltration"
    severity: str          # "high", "medium", "low"
    description: str
    involved_steps: list[int] = field(default_factory=list)  # Step indices
    confidence: float = 0.0  # 0.0-1.0


class ActionChainAnalyzer:
    """Analyzes action chains for dangerous compositions.

    Detects patterns where individually safe tool calls, when composed,
    create security vulnerabilities (arXiv:2605.14932 §IV.B).

    This fills the critical gap in the TrinityGuard-SARC bridge: the current
    bridge checks each action independently but misses chain-level attacks.
    """

    # Chain patterns that indicate specific attacks
    PRIVILEGE_ESCALATION_PATTERNS = [
        {
            "name": "file_read_to_exec",
            "description": "Read sensitive file, then execute with extracted data",
            "steps": [
                {"action_pattern": "file_fetch|read", "params": {"path": r".*\.env.*|.*\.ssh.*|.*password.*|.*secret.*"}},
                {"action_pattern": "exec", "params": None},
            ],
            "severity": "high",
        },
        {
            "name": "file_read_to_message",
            "description": "Read sensitive file, then exfiltrate via message",
            "steps": [
                {"action_pattern": "file_fetch|read", "params": {"path": r".*\.env.*|.*\.ssh.*|.*password.*|.*secret.*|.*key.*"}},
                {"action_pattern": "message", "params": None},
            ],
            "severity": "high",
        },
        {
            "name": "write_to_exec",
            "description": "Write a file, then execute it (sandbox escape)",
            "steps": [
                {"action_pattern": "write|file_write", "params": None},
                {"action_pattern": "exec", "params": None},
            ],
            "severity": "high",
        },
        {
            "name": "web_fetch_to_exec",
            "description": "Fetch external content, then execute it",
            "steps": [
                {"action_pattern": "web_fetch", "params": None},
                {"action_pattern": "exec", "params": None},
            ],
            "severity": "high",
        },
    ]

    COVERT_EXFILTRATION_PATTERNS = [
        {
            "name": "data_to_filename",
            "description": "Encode data in file names (potential covert channel)",
            "steps": [
                {"action_pattern": "file_fetch|read", "params": None},
                {"action_pattern": "write|file_write|exec", "params": None},
            ],
            "indicators": ["base64", "encode", "obfuscate"],
            "severity": "medium",
        },
        {
            "name": "rapid_small_messages",
            "description": "Rapid small messages may indicate covert channel exfiltration",
            "threshold_count": 10,
            "threshold_window_seconds": 60.0,
            "max_content_length": 200,
            "severity": "medium",
        },
    ]

    CROSS_DOMAIN_PATTERNS = [
        {
            "name": "cross_domain_data_flow",
            "description": "Data flowing from one domain to another through file operations",
            "steps": [
                {"action_pattern": "file_fetch|read", "params": None, "domain_change": True},
                {"action_pattern": "write|file_write|message", "params": None, "domain_change": True},
            ],
            "severity": "high",
        },
    ]

    def __init__(self, window_seconds: float = 300.0) -> None:
        """Initialize chain analyzer.

        Args:
            window_seconds: How far back to look for chain patterns (default 5 min).
        """
        self._chains: dict[str, list[ChainStep]] = defaultdict(list)  # agent_id -> steps
        self._window = window_seconds
        self._alerts: list[ChainAlert] = []

    def record_action(
        self,
        agent_id: str,
        action: str,
        params: dict[str, Any],
        domain_id: str,
        result_summary: str = "",
    ) -> list[ChainAlert]:
        """Record an action and analyze for chain patterns.

        Returns any alerts generated.
        """
        step = ChainStep(
            action=action,
            params=params or {},
            timestamp=time.time(),
            domain_id=domain_id,
            agent_id=agent_id,
            result_summary=result_summary,
        )

        self._chains[agent_id].append(step)

        # Prune old steps
        cutoff = time.time() - self._window
        self._chains[agent_id] = [
            s for s in self._chains[agent_id] if s.timestamp > cutoff
        ]

        # Analyze
        alerts = self._analyze(agent_id)
        self._alerts.extend(alerts)

        return alerts

    def _analyze(self, agent_id: str) -> list[ChainAlert]:
        """Analyze recent actions for dangerous chain patterns."""
        alerts: list[ChainAlert] = []
        steps = self._chains[agent_id]

        if len(steps) < 2:
            return alerts

        # Check privilege escalation patterns
        for pattern in self.PRIVILEGE_ESCALATION_PATTERNS:
            alert = self._match_chain_pattern(steps, pattern)
            if alert:
                alerts.append(alert)

        # Check covert exfiltration patterns
        for pattern in self.COVERT_EXFILTRATION_PATTERNS:
            alert = self._match_exfil_pattern(steps, pattern)
            if alert:
                alerts.append(alert)

        # Check cross-domain patterns
        for pattern in self.CROSS_DOMAIN_PATTERNS:
            alert = self._match_cross_domain_pattern(steps, pattern)
            if alert:
                alerts.append(alert)

        return alerts

    def _match_chain_pattern(
        self, steps: list[ChainStep], pattern: dict
    ) -> ChainAlert | None:
        """Match a multi-step chain pattern against recent actions."""
        required = pattern["steps"]
        if len(steps) < len(required):
            return None

        # Look for the pattern in the last N steps
        lookback = min(len(steps), len(required) + 3)  # Allow some slack
        recent = steps[-lookback:]

        # Find matching step sequences
        for i in range(len(recent) - len(required) + 1):
            matched = True
            matched_indices = []
            for j, req in enumerate(required):
                step = recent[i + j]
                if not re.match(req["action_pattern"], step.action, re.IGNORECASE):
                    matched = False
                    break

                # Check param patterns if specified
                if req.get("params"):
                    for key, pat in req["params"].items():
                        val = step.params.get(key, "")
                        if isinstance(val, str) and not re.search(pat, val, re.IGNORECASE):
                            matched = False
                            break

                matched_indices.append(len(steps) - lookback + i + j)

            if matched:
                return ChainAlert(
                    alert_type=f"chain:{pattern['name']}",
                    severity=pattern["severity"],
                    description=pattern["description"],
                    involved_steps=matched_indices,
                    confidence=0.85,
                )

        return None

    def _match_exfil_pattern(
        self, steps: list[ChainStep], pattern: dict
    ) -> ChainAlert | None:
        """Match covert exfiltration patterns."""
        # Rapid small messages pattern
        if "threshold_count" in pattern:
            recent = [s for s in steps if time.time() - s.timestamp < pattern["threshold_window_seconds"]]
            if len(recent) >= pattern["threshold_count"]:
                small_messages = [
                    s for s in recent
                    if s.action == "message"
                    and len(s.params.get("message", "")) < pattern.get("max_content_length", 200)
                ]
                if len(small_messages) >= pattern["threshold_count"]:
                    return ChainAlert(
                        alert_type=f"exfil:{pattern['name']}",
                        severity=pattern["severity"],
                        description=pattern["description"],
                        involved_steps=[i for i, s in enumerate(steps) if s in small_messages[-pattern["threshold_count"]:]],
                        confidence=0.6,
                    )

        # Indicator-based pattern
        if "indicators" in pattern:
            for i, step in enumerate(steps):
                action_str = str(step.params).lower()
                if step.result_summary:
                    action_str += " " + step.result_summary.lower()
                if any(ind in action_str for ind in pattern["indicators"]):
                    return ChainAlert(
                        alert_type=f"exfil:{pattern['name']}",
                        severity=pattern["severity"],
                        description=f"{pattern['description']} (indicator: {ind})",
                        involved_steps=[i],
                        confidence=0.5,
                    )

        return None

    def _match_cross_domain_pattern(
        self, steps: list[ChainStep], pattern: dict
    ) -> ChainAlert | None:
        """Match cross-domain data flow patterns."""
        required = pattern["steps"]
        if len(steps) < len(required):
            return None

        lookback = min(len(steps), len(required) + 5)
        recent = steps[-lookback:]

        for i in range(len(recent) - len(required) + 1):
            domain_changed = False
            matched = True

            for j, req in enumerate(required):
                step = recent[i + j]
                if not re.match(req["action_pattern"], step.action, re.IGNORECASE):
                    matched = False
                    break

                if req.get("domain_change") and j > 0:
                    if step.domain_id != recent[i + j - 1].domain_id:
                        domain_changed = True

            if matched and domain_changed:
                return ChainAlert(
                    alert_type=f"cross_domain:{pattern['name']}",
                    severity=pattern["severity"],
                    description=pattern["description"],
                    involved_steps=list(range(len(steps) - lookback + i, len(steps) - lookback + i + len(required))),
                    confidence=0.7,
                )

        return None

    def get_alerts(self, limit: int = 50) -> list[ChainAlert]:
        """Get recent alerts."""
        return self._alerts[-limit:]

    def clear_alerts(self) -> None:
        """Clear all alerts."""
        self._alerts.clear()

    def get_chain(self, agent_id: str) -> list[ChainStep]:
        """Get the action chain for an agent."""
        return self._chains.get(agent_id, [])


# ---------------------------------------------------------------------------
# 5. Unified OS Security Gate — Integrates with Bridge
# ---------------------------------------------------------------------------

@dataclass
class OSSecurityCheckResult:
    """Result of an OS security check."""
    component: str         # "isolation", "capability", "ipc", "chain"
    passed: bool
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)


class OSSecurityGate:
    """Unified OS security gate that integrates all 4 components.

    This is the primary integration point with the TrinityGuard-SARC bridge.
    It routes through all OS security components and produces a unified
    enforcement decision.
    """

    def __init__(
        self,
        enable_isolation: bool = True,
        enable_capabilities: bool = True,
        enable_ipc: bool = True,
        enable_chain_analysis: bool = True,
    ) -> None:
        self.isolation = IsolationDomainManager() if enable_isolation else None
        self.capabilities = CapabilityManager() if enable_capabilities else None
        self.ipc = IPCMediator() if enable_ipc else None
        self.chain_analyzer = ActionChainAnalyzer() if enable_chain_analysis else None

        self._enable_isolation = enable_isolation
        self._enable_capabilities = enable_capabilities
        self._enable_ipc = enable_ipc
        self._enable_chain_analysis = enable_chain_analysis

    def check_action(
        self,
        action: AgentAction,
        domain_id: str | None = None,
        agent_id: str | None = None,
    ) -> tuple[Decision, list[OSSecurityCheckResult]]:
        """Run all OS security checks on an action.

        Returns (decision, check_results).
        """
        results: list[OSSecurityCheckResult] = []

        # 1. Isolation check
        if self._enable_isolation and self.isolation and domain_id:
            allowed, reason = self.isolation.check_action(domain_id, action)
            results.append(OSSecurityCheckResult(
                component="isolation",
                passed=allowed,
                reason=reason,
                metadata={"domain_id": domain_id},
            ))

        # 2. Capability check
        if self._enable_capabilities and self.capabilities and agent_id:
            allowed, reason = self.capabilities.check_tool_access(
                agent_id, action.action, action.params
            )
            results.append(OSSecurityCheckResult(
                component="capability",
                passed=allowed,
                reason=reason,
                metadata={"agent_id": agent_id, "tool": action.action},
            ))

        # 3. IPC check (for message actions)
        if self._enable_ipc and self.ipc and agent_id and action.action == "message":
            target = action.params.get("target", action.params.get("recipient", ""))
            content = action.params.get("message", action.params.get("text", ""))
            if target:
                allowed, reason = self.ipc.mediate(
                    sender_id=agent_id,
                    recipient_id=str(target),
                    content=str(content),
                    direction=MessageDirection.OUTBOUND,
                )
                results.append(OSSecurityCheckResult(
                    component="ipc",
                    passed=allowed,
                    reason=reason,
                    metadata={"sender": agent_id, "recipient": target},
                ))

        # 4. Chain analysis (record action for composition detection)
        if self._enable_chain_analysis and self.chain_analyzer and agent_id:
            chain_alerts = self.chain_analyzer.record_action(
                agent_id=agent_id,
                action=action.action,
                params=action.params,
                domain_id=domain_id or "",
            )
            if chain_alerts:
                for alert in chain_alerts:
                    results.append(OSSecurityCheckResult(
                        component="chain",
                        passed=False,
                        reason=alert.description,
                        metadata={
                            "alert_type": alert.alert_type,
                            "severity": alert.severity,
                            "confidence": alert.confidence,
                        },
                    ))

        # Aggregate decision
        failed = [r for r in results if not r.passed]
        if failed:
            # Check for high-severity failures or any hard component failure
            # (isolation and capability failures are always hard blocks)
            hard_components = {"isolation", "capability", "ipc"}
            high_sev = [r for r in failed if r.metadata.get("severity") == "high"]
            hard_fail = [r for r in failed if r.component in hard_components]
            if high_sev or hard_fail:
                return Decision.BLOCK, results
            return Decision.ESCALATE, results

        return Decision.ALLOW, results

    def check_inbound_message(
        self,
        sender_id: str,
        content: str,
    ) -> tuple[bool, str]:
        """Check an inbound message for injection patterns."""
        if self._enable_ipc and self.ipc:
            return self.ipc.check_inbound(sender_id, content)
        return True, ""

    def setup_agent(
        self,
        agent_id: str,
        domain_type: DomainType = DomainType.AGENT,
        capabilities: list[dict[str, Any]] | None = None,
        parent_domain_id: str | None = None,
        ipc_policy: IPCPolicy | None = None,
    ) -> str:
        """Set up OS security for a new agent.

        Returns the domain ID.
        """
        # Create isolation domain
        domain_id = ""
        if self._enable_isolation and self.isolation:
            domain = self.isolation.create_domain(
                domain_type=domain_type,
                parent_id=parent_domain_id,
            )
            domain_id = domain.domain_id

        # Grant capability tokens
        if self._enable_capabilities and self.capabilities and capabilities:
            for cap in capabilities:
                self.capabilities.grant_token(
                    tool_pattern=cap.get("tool", "*"),
                    granted_by=cap.get("granted_by", "system"),
                    granted_to=agent_id,
                    max_uses=cap.get("max_uses"),
                    ttl_seconds=cap.get("ttl_seconds"),
                    params_constraint=cap.get("params_constraint"),
                )

        # Set IPC policy
        if self._enable_ipc and self.ipc and ipc_policy:
            self.ipc.set_policy(agent_id, ipc_policy)

        return domain_id

    def teardown_agent(self, agent_id: str, domain_id: str | None = None) -> None:
        """Tear down OS security for an agent."""
        if self._enable_capabilities and self.capabilities:
            self.capabilities.revoke_all_for_agent(agent_id)

        if self._enable_isolation and self.isolation and domain_id:
            self.isolation.destroy_domain(domain_id)

    def status(self) -> dict[str, Any]:
        """Get status of all OS security components."""
        status: dict[str, Any] = {}
        if self.isolation:
            status["isolation"] = {
                "active_domains": len(self.isolation.all_domains()),
                "domains": [
                    {
                        "id": d.domain_id,
                        "type": d.domain_type.value,
                        "actions": d.action_count,
                        "children": len(d.children),
                    }
                    for d in self.isolation.all_domains()
                ],
            }
        if self.capabilities:
            status["capabilities"] = {
                "active_tokens": sum(1 for t in self.capabilities._tokens if t not in self.capabilities._revoked),
                "agents": list(self.capabilities._agent_tokens.keys()),
            }
        if self.ipc:
            status["ipc"] = {
                "policies": len(self.ipc._policies),
                "messages_logged": len(self.ipc._message_log),
                "blocked_domains": list(self.ipc._blocked_domains),
            }
        if self.chain_analyzer:
            status["chain_analysis"] = {
                "tracked_agents": len(self.chain_analyzer._chains),
                "alerts": len(self.chain_analyzer.get_alerts()),
            }
        return status
