"""
The connector boundary.

Every source of truth -- the synthetic generator, an AWS IAM snapshot reader, a
CloudTrail reader -- is a peer behind this one interface. The synthetic
generator is not a throwaway stub: it is a first-class connector that happens to
invent its records, which is what lets the whole engine be tested deterministically
forever while real connectors are swapped in underneath.
"""

from datetime import datetime
from typing import Iterator, Optional, Protocol, runtime_checkable

from app.evidence.models import Evidence, SourceRef


@runtime_checkable
class EvidenceConnector(Protocol):
    """
    Structural contract for anything that can produce Evidence.

    Deliberately a Protocol rather than an ABC: a connector satisfies this by
    having the right shape, so a source adapter never has to import and subclass
    engine internals. That keeps the dependency arrow pointing inward and makes
    third-party or ad-hoc connectors trivial to write.
    """

    def source_ref(self) -> SourceRef:
        """Identifies the concrete scope this connector reads from."""
        ...

    def collect(
        self,
        *,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> Iterator[Evidence]:
        """
        Yields Evidence observed within [since, until].

        Returns an iterator rather than a list on purpose. CloudTrail for a real
        account is far too large to materialize, and every downstream stage can
        consume a stream, so bounded memory is available for free as long as no
        connector breaks the contract by building a list internally.

        Implementations must yield Evidence whose observed_at falls inside the
        window when one is given; filtering is the connector's job because a real
        source can usually push the predicate down to the API and avoid the
        transfer entirely.
        """
        ...
