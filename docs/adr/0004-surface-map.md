# ADR-0004: The Application Surface Map is the central intermediate representation

**Status:** proposed · **Date:** 2026-09-13 · **PRD:** §4.2, §6.4 · **Build order:** items 15–23

## Context

Static analysis cannot see authorization. It sees a route handler and a database query; it
cannot know whether the caller was allowed. That is why every SAST tool is weak on Broken
Access Control — the top OWASP category, and the one AI-assisted code gets wrong most.

## Decision

Build a normalised inventory of HTTP entry points — route handlers, Server Actions, pages,
middleware — each with its method, normalised path pattern, parameters, handler symbol,
reachable data access, and the authentication and authorization checks found on any path
from entry to data access. Record what could **not** be resolved, explicitly.

Everything keys off this: the access-control rules, the API rules, verification plan
generation, the route table in the report, and — critically — the `surfaceId` join to
runtime evidence emitted by `security-core`.

## Consequences

- This is the hardest engineering in the product and the riskiest part of the schedule.
  Timebox to two weeks (PRD §20.4).
- Incompleteness must be **visible**, never silent. An unresolved call graph lowers a
  finding's confidence from `firm` to `tentative` and is printed in the coverage line.
- The map is also the most valuable long-term artifact: an endpoint inventory with
  authorization posture, tracked over time.

## What would change our mind

If real-world Next.js diversity makes the map unreliable, ship it as a route inventory
only (no authorization reachability) and lean harder on V2 runtime evidence for the
access-control story. The evidence bridge works without a perfect static map.
