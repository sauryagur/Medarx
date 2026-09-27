"""Component J: the application API.

The HTTP surface, the composition root, and the authorization boundary. The
modules here, and what each is for:

- `app` — `create_app`, the **one** composition point. Every component is built
  here, once, and a test reaches the same objects the server does.
- `middleware` — request identity, the body cap, and the `500` that is a problem
  document rather than a traceback. Around every request, for all five paths.
- `schemas` — the request and response bodies, transcribed from
  `contracts/openapi.yaml` field for field, every closed schema closed here too.
- `authz` — the synthetic Phase 1 scope. **Not authentication**: the contract
  declares `security: []`, and anyone who can reach this server can present any
  scope. It models and enforces an authorization boundary and nothing more.
- `wiring` — the boundary's own decisions: request identity, problem documents,
  and the one translation between the contract's function names and the kernel's.
- `surface` — component J's own action codes, and the audit record a refusal at
  this surface leaves behind.
- `routes_functions`, `routes_approval`, `routes_policy`, `routes_audit` — the
  five contract paths and no others. No route constructs a component.

The normative source for what blocks is design §6; the normative source for what
the bodies look like is `contracts/openapi.yaml`, which `app` serves verbatim.
"""

from medarx.api.app import create_app

__all__ = ["create_app"]
