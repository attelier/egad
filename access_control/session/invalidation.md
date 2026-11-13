---
path: [access_control, session, invalidation]
cwe: [CWE-613]
owasp_top10: [A07:2021]
capec: [CAPEC-60]
status: draft
updated: 2026-11-13
---

# Session Invalidation (CWE-613)

A server-side session or token stays valid after an event that was supposed to
end it. The mechanism is the same in every case; what decides the score is
**which event failed to tear it down**, and how completely: a control the victim
actually relies on to evict an attacker, or a convenience, and whether anything
usable is left behind. The deciding question is whether the finding hands anyone a
capability they did not already have.

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
- This scenario is the server-side-only failure: logout clears the session on the
  client and only the server-side session outlives it. If logout also leaves a
  usable session in the browser, see the Q&A below.

**Q&A**

*So it's always Informational?* Yes, in this shape. Administrative or upstream
revocation that should have ended a session but isn't re-checked at an endpoint is
the same: no new capability over whoever already held the token.

*What if logout leaves the session usable in the browser too?* That is a different
finding and it is not Informational. The next person to use that browser gets a
working session they never had, which is a new capability, so score it on what that
session reaches. Bugcrowd's VRT draws the same line: *On Logout (Server-Side Only)*
is P5, while *On Logout (Client and Server-Side)* is P4.

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

*Why is this scored when logout isn't?* Because of what the control is **for**. A
password change or reset is the account-recovery mechanism whose specified function
is to terminate other active sessions — the step an account owner is told to perform
to shut out anyone already in. When it silently fails, a security control does not
perform the function it exists to provide, and the documented recovery path is
defeated. The attacker gains no new capability — which is why this stays `VI:L`, not
higher — but a recovery control failing at the one thing it is specified to do is a
vulnerable-system integrity impact on its own. Logout carries no such eviction
function; it drops the local cookie as a convenience, so its failure adds nothing
over whoever already held the token.

*Does the taxonomy back this?* In part, and the exact wording matters. Bugcrowd's
VRT rates *Failure to Invalidate Session > On Password Reset and/or Change* at P4,
and it rates *On Logout (Server-Side Only)*, which is the Scenario 1 shape, at P5.
It also rates *On Logout (Client and Server-Side)* at P4, so the taxonomy does not
separate password reset from logout as such. What it separates is a failure that
leaves someone holding a usable session from one that does not, which is the same
line drawn here.

### SCENARIO 3 — Session survives a privilege downgrade or account deletion

```
CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N
```

**Reasoning**

- Unlike Scenarios 1 and 2, the surviving session now **retains rights the account
  no longer has**. The intended state changed — a role was reduced, or the account
  was removed outright — and the session keeps the pre-change privileges. That is a
  real capability against the intended authorization state, not merely the
  persistence of access the account still legitimately holds, which is why this one
  scores on the impact axes in its own right rather than resting on the
  recovery-control argument of Scenario 2.
- **AT:P** the attacker's session must already be active at the moment of the
  downgrade or deletion.
- **PR:L** the attacker held the account whose privileges were cut, or whose
  existence was revoked.
- **VC:L / VI:L (default)** the session still reads and writes at the former
  privilege level — data and actions the account is no longer authorized for. Real
  but bounded at the leaf default; both rise by demonstrated magnitude. A retained
  admin shown to create users or alter other principals' data is `VI:H`; a broad read
  of data the downgraded or deleted principal should no longer reach is `VC:H`.
- **SC/SI/SA:N** the impact lands on the vulnerable application's own authorization
  state; no distinct subsequent system is reached unless a PoC demonstrates one.

**Q&A**

*Why does this score when logout doesn't?* Because the account's authorized rights
actually shrank. Logout removes nothing the
holder didn't already have, and a password change leaves the account's rights intact
while only failing to evict. Here the authorization state was reduced or revoked and
the session outlives it, so the holder exercises privileges the system has already
decided they should not have — a capability against the intended state, scored on
`VC`/`VI` by what the retained access demonstrably reaches, not on intent.

*Why only Low by default?* The retained capability is bounded by what that account
could already do, so nothing beyond its former privilege is unlocked. The default is
`VC:L/VI:L`, which scores 2.3, the same number as Scenario 2. The default is not what
separates them. Scenario 2 sits at its floor because the account's rights never
changed, so there is nothing for a PoC to raise; here the rights were reduced or
revoked, and the metrics rise with what the retained access is demonstrably shown to
reach. A demonstrated retained privileged write is `VC:L/VI:H`, which scores 6.0.

Bugcrowd's VRT rates *Failure to Invalidate Session > On Permission Change* as
Varies, which is the same treatment: the category has no fixed severity because it
depends on what the retained privilege reaches.

## Notes

**Per-session revocation nullifies Scenario 2.** If the application offers working
per-session revocation — a session manager that lists active sessions and lets the
user delete a specific one while keeping their own — then Scenario 2 drops to
Informational. The victim has a dedicated, working control to evict the attacker,
so the password change not also doing it denies them nothing. The revocation must
actually terminate the targeted session server-side; if *it* is what silently
fails, that is the finding, not the password change.

It does not reach Scenario 3. There the account's rights were reduced or revoked, so
the session should have been ended by the system that made that decision, not by the
account holder noticing and clearing it by hand. A session manager the user operates
is not the control that failed.

**Reset-token reuse is a different leaf.** "Reset token not invalidated after a new
token / after use / after password change" is weak password-reset implementation,
anchored to the Bugcrowd VRT priorities, not scored here.

## Corrections

- **2026-11-11** New leaf. Splits the class by the triggering event: logout (and
  equivalent revocations) is Informational — no new capability over whoever held
  the token — while password change/reset carries a Low vulnerable-system integrity
  impact because it is the remediation control the victim relies on. Added the
  per-session-revocation carve-out that returns Scenario 2 to Informational.
- **2026-11-12** Review pass. Dropped Scenario 1's "chained to token-theft" Q&A — it
  is not an aggravating metric and has no CVSS 4.0 base representation. Rewrote
  Scenario 2's Q&A off the subjective "intent" framing onto two objective legs: what
  the control is *for* (a recovery mechanism whose specified function is to terminate
  other sessions), and the taxonomy (Bugcrowd VRT rates *Failure to Invalidate
  Session → On Password Reset and/or Change* as its own P4 category, distinct from
  logout); vector unchanged. Added Scenario 3 — session surviving a privilege
  downgrade or account deletion — which scores on its own impact axes (`VC:L/VI:L`
  default, Low 2.3, rising by demonstrated magnitude) because the session retains
  rights the account no longer has, a capability against the intended authorization
  state rather than mere persistence of still-authorized access.
- **2026-11-13** Second review pass. Corrected the VRT citation in Scenario 2 against
  the canonical taxonomy: *On Logout (Client and Server-Side)* is P4 as well, so the
  split is not logout against password reset but whether a usable session is left
  behind. Bounded Scenario 1 to the server-side-only shape (VRT P5) and added the
  browser-usable case, which is not Informational. Removed Scenario 3's claim to score
  above Scenario 2, whose 2.3 default it equals, and cited VRT *On Permission Change*
  (Varies). Scoped the per-session-revocation carve-out away from Scenario 3 and
  widened the opening to cover how completely the teardown failed.
