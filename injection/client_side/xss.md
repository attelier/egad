---
path: [injection, client_side, xss]
cwe: [CWE-79]
owasp_top10: [A03:2021]
capec: [CAPEC-591]
status: canonical
updated: 2026-11-13
---

# Cross-Site Scripting (XSS)

Attacker-controlled input is reflected or stored and then executed as script in
another user's browser. What moves the score is not "XSS happened" but *what the
script can reach*: application data it reads or writes through the victim's
session, a live session cookie, privileged users, or just the page's own
rendering.

Three things decide almost every XSS call:

- **Reflected vs. stored** sets User Interaction. Reflected needs a crafted link
  (`UI:A`); stored fires on page load (`UI:P`).
- **What the executed script demonstrably reads or writes** sets `VC`/`VI`.
  Same-origin script runs with the victim's ambient session, so it reads and writes
  application data *as the victim* — scored by demonstrated magnitude, never
  potential. This is the main lever and it does **not** depend on the cookie (see
  Notes: Session-riding).
- **Cookie exfiltration** is a *second, independent* lever: a stealable session
  cookie makes that access portable and durable — replayable after the victim
  leaves — turning in-session impact into a temporary account takeover. An
  `HttpOnly` cookie that can't be stolen caps that portability, **not** the
  in-session reach of the script.

## Scenarios

### SCENARIO 1 — Reflected, no cookie exfiltration (HttpOnly)

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N
```

**Reasoning**

- **UI:A** requires a conscious click on a crafted link.
- **VC:N / VI:N** nothing on the vulnerable system is read or changed.
- **SI:L** the payload alters rendering in the victim's browser, which is the
  subsequent system.

**Q&A**

*Why not High?* Here the PoC shows only execution, so nothing lifts it above
browser-rendering impact (`SI:L`). Execution on its own is the finding, not the
severity. To move up, demonstrate what the script reaches — application data
read/written through the victim's session, a stealable/reusable session, or a
privileged sink; each raises `VC`/`VI` by its demonstrated magnitude (see Notes:
Session-riding). Potential reach is not scored.

*Why isn't an alert box enough?* It proves execution, exactly `SI:L`, nothing more.
Impact needs a demonstrated reach, not a proof of concept.

### SCENARIO 2 — Reflected, cookie exfiltration to session hijack

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:L/SA:N
```

**Reasoning**

- **UI:A** requires a conscious click on a crafted link.
- **VC:H** the stolen cookie is a standing credential for the account, usable from
  the attacker's own machine for the life of the session, so the read capability is
  not confined to the page or the visit. The impact lands on the vulnerable system.
- **VI:L (default)** the write capability is the same standing credential, but
  nothing persistent is written into the application and no other account's stored
  data is reached, which are the two routes to `VI:H` in this leaf. Rises on a
  demonstrated write past that account's own scope.
- **SC:N** the cookie is not sensitive in itself; what matters is what it grants.
- **SI:L** the payload alters rendering in the victim's browser.

**Q&A**

*Why VC and not SC?* The stolen cookie grants access to the vulnerable
application, so the confidentiality loss is the app's (`VC`). The cookie itself is
not the sensitive asset; what it unlocks is.

*Why VC:H and not VC:L?* Not by default. It is High because what the attacker ends
up with is a standing credential, assessed by what the account behind it holds. Where
that account holds data of consequence it is `VC:H`; where it genuinely grants little,
no data worth reading and no actions worth taking, it is `VC:L`. Say which in the
finding. Note that this is above where FIRST puts session abuse that stays inside the
page, `VC:L`, and deliberately so: a stolen credential outlives the page.

*Why is VI only Low?* Because neither route to `VI:H` is present. Nothing persistent
is written into the application, and no stored data belonging to another account is
reached. A reflected payload yields one account's write capability and no more. Show
a write past that account's own scope and it rises.

### SCENARIO 3 — Stored, no cookie exfiltration

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N
```

Default vector. `VI` is the variable metric here: `VI:L`, rising to `VI:H` on either
of the two routes this leaf allows, demonstrated defacement-grade integrity impact
(see Notes: Defacement) or a demonstrated write past the victim's own scope (see
Notes: Session-riding). `VC` is
variable the same way: `VC:N` by default, rising when the script is shown to read
application data through the victim's session, by magnitude (see Notes:
Session-riding).

**Reasoning**

- **UI:P** the payload runs on render, with no specific action from the victim,
  but the victim needs to be present during exploitation.
- **VI:L (default)** the attacker wrote persistent, attacker-controlled data into
  the app's store, which is a vulnerable-system integrity impact on its own terms,
  independent of rendering (that is the `SI` axis). Real but limited; rises to
  `VI:H` only with demonstrated defacement-grade control (see Notes).
- **SI:L** same browser-rendering impact as the reflected case.

**Q&A**

*Why not always High?* `VI` is not automatically `High` for stored XSS.
Persistence widens *who* is affected (anyone who loads the page) but not by itself
*what* the script reaches. Absent demonstrated defacement-grade impact, `VI:L` is
the honest default; `VI:H` must be earned by the PoC, not assumed from the bug
class.

*Why is VI Low here but None in the reflected no-cookie case?* Persistence. The
attacker has written attacker-controlled data into the application's own store,
which is an integrity impact on the vulnerable system whether or not anybody loads
the page, and separate from what the render does (that is the `SI` axis). A reflected
payload that reaches nothing leaves the vulnerable system untouched (`VI:N`).

### SCENARIO 4 — Stored, cookie exfiltration

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:L/SA:N
```

**Reasoning**

- **UI:P** the payload runs on render, no specific action from the victim, but the
  victim needs to be present during exploitation.
- **VC:H** any user who loads the page can be hijacked, privileged accounts
  included.
- **VI:H** the demonstrated impact resembles HTML-injection-grade defacement and
  the payload can act against other users' stored data, which justifies `VI:H`
  under FIRST (see Notes: Defacement).
- **SC:N** the cookie is not sensitive in itself; what matters is what it grants.
- **SI:L** subsequent-system impact is still the victim's browser rendering.

**Q&A**

*Why VC and not SC?* The stolen cookie grants access to the vulnerable
application, so the confidentiality loss is the app's (`VC`). The cookie is not
the sensitive asset; what it unlocks is.

*Why is VI High here but Low in Scenario 3?* Two things carry it, and neither is the
number of users. The stolen session supplies the write capability without a separate
PoC: holding a reusable credential for an account is the capability to act as that
user, where Scenario 3 has to demonstrate each write it claims. And because the
payload is stored it takes credentials from accounts other than the attacker's own,
so the writes reach stored data that belongs to those accounts, which is the basis
the Defacement
note already sets for `VI:H`. Scenario 2 has the first of those and not the second:
that basis is written for stored payloads, and a reflected one reaches only the
account of whoever clicked, so there is no route to `VI:H` for it in this leaf.

*Can Scenario 3 reach this same vector?* Yes, and that is the expected result rather
than a mistake. A Scenario 3 PoC that demonstrates both reads and writes reaches
`VC:H/VI:H` and scores 8.6, the same as this scenario, because the impact on the
application is the same. What the stolen cookie adds over that is portability and
durability: the attacker replays the session from their own machine after the victim
has gone. Base CVSS 4.0 has no metric for that, so it belongs in the report text and
not in the vector.

*Why not Critical?* `SI` stays Low. The script rewrites what a victim's browser
renders; it does not compromise the subsequent system's own integrity. Critical
needs a subsequent-system impact this lacks, for example the script reaching a
server-side privileged sink. Show that and it is a new scenario, put it in the
report.

## Notes

The integrity asymmetry between the two cookie cases (`VI:L` in Scenario 2, `VI:H`
in Scenario 4) is deliberate, and it is not the number of users. A stored payload
writes attacker-controlled data into the application and takes a session from every
loader, so its writes reach stored data belonging to accounts other than any one
victim. A reflected payload does neither: nothing of it persists in the application
and it yields a single account. Those are the two routes to `VI:H` below, and
Scenario 2 is on neither.

**Defacement and VI.** There are two routes to `VI:H` and a finding needs one of
them. The first is persistent, attacker-controlled modification of content or data
beyond the transient render, that is, HTML-injection-grade defacement or action
against other users' stored data. The second is a demonstrated write past what the
victim's own account may do, which is the magnitude rule under Session-riding and
does not require persistence. The number of users exposed is an indicator of reach,
not by itself a basis for `VI:H` under FIRST; the integrity impact is what sets the
metric.

Self-XSS (the victim must paste the payload into their own console or a field only
they see) is not scored as XSS impact here. There is no realistic attacker path,
so it does not clear the bar on its own.

If cookie-bombing DoS is demonstrated on any of the cases, subsequent-system
availability can climb from `SA:N` to `SA:L`. For now we consider this to not
reasonably reach `SA:H` under any circumstances, as that would imply a general
unusability of the subsequent system. Credits to Kaiksi for the note on this matter.

**Session-riding and `HttpOnly`.** No cookie exfiltration does not mean no impact.
The script runs on the application's own origin, inside the page, so it can send
requests to the application and read the responses. That is what `HttpOnly` leaves
untouched: it stops JavaScript reading the cookie string, while the browser goes on
attaching the cookie to every request the page makes.

This is not CSRF and does not score like it. A cross-site request is sent blind,
because the attacker's origin is not allowed to read the response, which is why a
CSRF token or `SameSite` defeats it. Script running in the page reads the response,
and reads the CSRF token out of the page as well, so neither defence applies. Being
able to read is what lets `VC` move at all; CSRF would only ever reach `VI`.

Score `VC` and `VI` from what the PoC demonstrates, and expect any combination.
Impersonating the user or automating application actions carries no default
severity. Reads and writes confined to what the victim's own account may already do
are Low. High needs the demonstration to go past that scope: an administrative
function, other users' records, a whole-resource read, a critical field such as
stored bank details. Demonstrated only: potential reach is not scored, or every XSS
would be Critical.

Deletion stays on `VI`. A script that destroys the victim's records is performing a
write, and `VA` is live only where the service stops working, which a script in a
browser does not do. That is the rule set in `access_control/object_level/idor` and
it holds here.

FIRST's CVSS v4.0 Examples document works both ends of that range, and it is worth
reading them together rather than citing only the high one. For CVE-2022-24682 it
adds a variation titled impact to the vulnerable application and scores it
`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:N`, base 5.1, on the
reasoning that user sessions could be abused to extract data from the application
and user privileges to modify or delete it. That is ordinary session-scoped abuse and
it is Low. For CVE-2024-55228 (Dolibarr) it scores
`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N`, base 8.5, for an
expanded impact reaching the application itself. Both vectors are FIRST's own, from
that document rather than from the CVE records. We part from the second on one
metric: it carries `VA:H`, and our availability rule does not reach `VA` unless the
service itself stops.

## Corrections

- **2026-07-08** Scenario 4 corrected from `VI:L` to `VI:H`. The intended reasoning
  was high vulnerable-system integrity (any loader affected, not one clicker). With
  `VI:L` the vector scores a full point lower, so the derived score now follows the
  reasoning instead of the typo.
- **2026-07-11** Reconsidered `VI:H` in stored situations to a FIRST-compliant basis
  (the H/L difference should not rest only on the number of users affected), moving
  Scenario 3 to a `VI:L` default that rises to `VI:H` only on demonstrated
  defacement-grade impact, while keeping a general indication of impact due to the
  extent of users exposed. Additionally added potential availability impact thanks
  to Kaiksi's comments on a recent report.
- **2026-07-11 (2)** Rewrote Scenario 4's VI Q&A to state the Scenario 3 vs 4
  distinction directly, absorbing an argument raised in review. Scenario 4's `VI:H`
  is not justified by cookie exfiltration as a confidentiality mechanism (that is
  `VC:H`) but by the authenticated write access a stolen session confers: acting as
  the victim is a demonstrated integrity capability, which the 07-11 principle
  requires. Also tightened Scenario 3's `VI:L` to rest on persistent
  attacker-controlled data written to the app's store, independent of rendering
  (the `SI` axis), rather than on rendered content.
- **2026-11-13 (2)** Sweep for places that still encoded the pre-11-11 rule, after
  review found the elevation rule restated in the Notes while four older passages
  still justified metrics by how many users a payload reaches. Scenario 2's `VC:H` now
  rests on the stolen cookie being a standing credential that outlives the page, with
  the divergence from FIRST's `VC:L` stated, rather than on a default-High reading of
  session access. Scenario 2's `VI:L` and the first Notes paragraph rest on neither
  route to `VI:H` being present rather than on the single clicker. The Defacement note
  and Scenario 3's header now name both routes, defacement-grade impact and a
  demonstrated write past the victim's own scope, which were previously two different
  tests in two places. The opening list of what the script can reach now includes
  application data, which the intro calls the main lever. Scenario 3's persistence
  Q&A now rests on attacker-controlled data being in the application's store rather
  than on the render and on every loader, and Scenario 4's basis is stated as whose
  stored data the writes reach rather than how many loaders supply a session. No
  vector changed.
- **2026-11-13** Second review pass. Scenario 4's `VI` Q&A no longer rests on cookie
  exfiltration conferring write access, which contradicted the intro and the note; it
  rests on the stolen session supplying that capability plus the Defacement basis of
  writes reaching other users' stored data, which Scenario 2 lacks. The Session-riding
  note argues from same-origin read access rather than from a credentialed request,
  which is the CSRF mechanism, and says why CSRF tokens and `SameSite` do not apply.
  Magnitude carries no default: impersonation and automation score by demonstration,
  session-scoped at Low, High only past the victim's own scope. Dropped the
  cross-tenant example, kept deletion on `VI` per the IDOR leaf, and cited both ends
  of FIRST's range instead of only Dolibarr, whose `VA:H` we do not follow.
- **2026-11-12** Consolidation pass after review (elevation rule read finicky when
  stated in four places with drifting wording). The **Session-riding note is now the
  single source of truth** for how `VC`/`VI` rise on demonstrated in-app impact;
  the intro, Scenario 1's Q&A and Scenario 3's header defer to it in one line instead
  of re-deriving it. Reordered the intro so the primary lever (what the script
  demonstrably reads/writes) comes first and cookie exfiltration is clearly the
  secondary, portability lever. No scenario vector changed; the baselines stand.
- **2026-11-11** Added a third deciding factor and the Session-riding note. `VC`/`VI`
  in the no-cookie scenarios (1 and 3) are variable by the demonstrated in-app impact
  of the executed script, because same-origin credentialed requests ride the victim's
  session even when the cookie is `HttpOnly`. Corrected the intro's second point:
  "no reachable cookie keeps it low" was wrong — a non-exfiltratable cookie caps the
  *portability* of the session, not the in-session reach of the script. No scenario
  vector changed; the baselines stand and now explicitly rise on demonstrated
  reads/writes. Departs from treating cookie-exfil as the sole elevation path;
  aligns with FIRST's expanded-impact example (CVE-2024-55228, Dolibarr).
