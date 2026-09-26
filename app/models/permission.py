from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

from app.common.validation import validate_non_empty_str, validate_tz_datetime
from app.models.capability import Capability


class GrantLifecycle(Enum):
    """
    How a grant is held over time.

    This is the central concept of a zero-standing-privilege engine, which is why
    it replaced a `standing: bool`. The entire product thesis is converting
    always-on access into requested, expiring access -- so the difference between
    "holds admin" and "may request admin, 4h TTL, approval required" is precisely
    the risk reduction being measured. A boolean cannot express it, and an engine
    that cannot express it cannot show that a remediation worked.
    """

    STANDING = "standing"          # always on, no expiry -- what ZSP exists to eliminate
    TIME_BOUND = "time_bound"      # active now, but expires
    JIT_ELIGIBLE = "jit_eligible"  # not active; the identity may request it
    ELEVATED = "elevated"          # a JIT grant currently inside its elevation window


@dataclass(frozen=True)
class Permission:
    """
    An *effective* grant: this identity can perform this action on this resource.

    Effective, not attached. In a real cloud estate this is the output of policy
    evaluation (identity policies, resource policies, boundaries, SCPs,
    conditions), not something read directly off a dump.
    """

    id: str
    identity_id: str
    resource_id: str
    action: Capability
    lifecycle: GrantLifecycle = GrantLifecycle.STANDING
    granted_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        validate_non_empty_str(self.id, "id")
        validate_non_empty_str(self.identity_id, "identity_id")
        validate_non_empty_str(self.resource_id, "resource_id")
        if not isinstance(self.action, Capability):
            raise TypeError(
                f"action must be a Capability, got {type(self.action).__name__}"
            )
        if not isinstance(self.lifecycle, GrantLifecycle):
            raise TypeError(
                f"lifecycle must be a GrantLifecycle, got {type(self.lifecycle).__name__}"
            )
        if self.granted_at is not None:
            validate_tz_datetime(self.granted_at, "granted_at")
        if self.expires_at is not None:
            validate_tz_datetime(self.expires_at, "expires_at")

        # A grant that claims to expire but carries no expiry is a standing grant
        # lying about itself. Left unchecked it inflates the "we have reduced
        # standing access" number that this engine exists to report honestly.
        if self.lifecycle in _EXPIRING_LIFECYCLES and self.expires_at is None:
            raise ValueError(
                f"lifecycle {self.lifecycle.value} requires expires_at"
            )
        if (
            self.expires_at is not None
            and self.granted_at is not None
            and self.expires_at < self.granted_at
        ):
            raise ValueError("expires_at must not precede granted_at")

    # --- Derived facts (no interpretation) ---

    @property
    def is_standing(self) -> bool:
        """Always-on with no expiry. The population ZSP tries to drive to zero."""
        return self.lifecycle is GrantLifecycle.STANDING

    def is_expired_at(self, evaluation_time: datetime) -> bool:
        """
        An expiring grant still present in the estate past its expiry.

        Not merely harmless bookkeeping: it usually means revocation failed, so
        the access may well still work.
        """
        validate_tz_datetime(evaluation_time, "evaluation_time")
        return self.expires_at is not None and evaluation_time > self.expires_at

    def confers_access_at(self, evaluation_time: datetime) -> bool:
        """Whether this grant gives access *right now*, without a request."""
        validate_tz_datetime(evaluation_time, "evaluation_time")
        if self.lifecycle is GrantLifecycle.STANDING:
            return True
        if self.lifecycle is GrantLifecycle.JIT_ELIGIBLE:
            return False
        if self.granted_at is not None and evaluation_time < self.granted_at:
            return False
        return not self.is_expired_at(evaluation_time)


_EXPIRING_LIFECYCLES = frozenset(
    {GrantLifecycle.TIME_BOUND, GrantLifecycle.ELEVATED}
)
