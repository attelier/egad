---
path: [access_control, session, invalidation]
cwe: [CWE-613]
owasp_top10: [A07:2021]
capec: [CAPEC-60]
status: draft
updated: 2026-11-11
---

# Session Invalidation (CWE-613)

A server-side session or token stays valid after an event that was supposed to
end it. The mechanism is the same in every case; what decides the score is
**which event failed to tear it down** — a control the victim actually relies on
to evict an attacker, or a convenience. The deciding question is whether the
finding hands anyone a capability they did not already have.

Borders `injection/client_side/xss` (which prices session access, not its
lifetime) and `access_control/object_level/idor`.

## Scenarios

### SCENARIO 1 — Logout does not invalidate the session

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N
```

**Reasoning**

- Anyone who can use the surviving session already holds a valid token, so they
  already have exactly the access it grants. The failed logout adds **no new
  capability**, so every impact metric is `N`.
- Logout is a client-side convenience (dropping the local cookie). Obtaining the
  token in the first place is a separate flaw that must be demonstrated on its own.

**Q&A**

*So it's always Informational?* Yes, on its own. Administrative or upstream
revocation that should have ended a session but isn't re-checked at an endpoint is
the same shape — no new capability over whoever already held the token.

*When does it matter?* Only chained to a demonstrated token-theft primitive, and
then the theft is the finding. Score that, not the non-invalidation.

### SCENARIO 2 — Password change or reset does not invalidate existing sessions

```
CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N
```

**Reasoning**

- **AT:P** an attacker session must already be active at the moment of the change.
- **PR:L** the attacker already holds the account/session that should have been
  evicted.
- **VC:N** no data is divulged beyond what that already-authenticated session
  could see; what breaks is access-control integrity, not confidentiality.
- **VI:L** the failure of that control is a vulnerable-system integrity impact,
  bounded to Low unless a higher-impact write is separately demonstrated.

**Q&A**

*Why is this scored when logout isn't?* Intent. A password change or reset is the
action a user performs specifically to respond to a suspected compromise; its
purpose is to evict other sessions. When it silently fails, the one control the
victim invokes to remove the attacker does nothing. That has security meaning even
though the attacker gains no new capability — which is why it is Low, not higher.

*Why not higher than Low?* The attacker already had the session; nothing new is
read or reached. `VC:N`, and `VI` stays `L` unless the PoC shows a materially
larger write than the persistence of the existing access.

## Notes

**Per-session revocation nullifies Scenario 2.** If the application offers working
per-session revocation — a session manager that lists active sessions and lets the
user delete a specific one while keeping their own — then Scenario 2 drops to
Informational. The victim has a dedicated, working control to evict the attacker,
so the password change not also doing it denies them nothing. The revocation must
actually terminate the targeted session server-side; if *it* is what silently
fails, that is the finding, not the password change.

**Reset-token reuse is a different leaf.** "Reset token not invalidated after a new
token / after use / after password change" is weak password-reset implementation,
anchored to the Bugcrowd VRT priorities, not scored here.

## Corrections

- **2026-11-11** New leaf. Splits the class by the triggering event: logout (and
  equivalent revocations) is Informational — no new capability over whoever held
  the token — while password change/reset carries a Low vulnerable-system integrity
  impact because it is the remediation control the victim relies on. Added the
  per-session-revocation carve-out that returns Scenario 2 to Informational.
