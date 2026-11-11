---
path: [injection, client_side, xss]
cwe: [CWE-79]
owasp_top10: [A03:2021]
capec: [CAPEC-591]
status: canonical
updated: 2026-11-11
---

# Cross-Site Scripting (XSS)

Attacker-controlled input is reflected or stored and then executed as script in
another user's browser. What moves the score is not "XSS happened" but *what the
script can reach*: a live session cookie, privileged users, or just the page's
own rendering.

Three things decide almost every XSS call:

- **Reflected vs. stored** sets User Interaction. Reflected needs a crafted link
  (`UI:A`); stored fires on page load (`UI:P`).
- **Cookie exfiltration** is the classic lever on confidentiality/integrity: a
  stealable session cookie is a temporary account takeover, durable and portable
  beyond the victim's visit. It is not the only lever, and an `HttpOnly` cookie
  that cannot be exfiltrated does not by itself keep impact low (see the next
  point).
- **Demonstrated in-app impact of the executed code** moves `VC`/`VI` on their
  own. Same-origin script runs with the victim's ambient session, so a
  credentialed `fetch`/`XHR` reads or writes application data *as the victim
  without ever reading or exfiltrating the cookie* (`HttpOnly` does not stop a
  credentialed request). `VC`/`VI` keep the scenario's baseline and rise with
  what the PoC actually shows the script read or write — demonstrated, never
  potential.

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

*Why not High?* Here the PoC shows only execution, so nothing lifts it above the
browser-rendering impact. Execution on its own is the finding, not the severity.
To move up, show something the script actually reaches: application data it reads
or writes through the victim's session (same-origin authenticated requests, no
cookie needed — see Notes: Session-riding), a stealable/reusable session, or a
privileged sink. Any of those raises `VC`/`VI` by its demonstrated magnitude.

*Why isn't an alert box enough?* It proves execution, which is exactly `SI:L`, and
nothing more. Impact needs a reachable sink, not a proof of concept.

### SCENARIO 2 — Reflected, cookie exfiltration to session hijack

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:L/VA:N/SC:N/SI:L/SA:N
```

**Reasoning**

- **UI:A** requires a conscious click on a crafted link.
- **VC:H** stealing the session cookie is a temporary account takeover; the impact
  lands on the vulnerable system.
- **VI:L** changes are possible but scoped to the single victim who clicks.
- **SC:N** the cookie is not sensitive in itself; what matters is what it grants.
- **SI:L** the payload alters rendering in the victim's browser.

**Q&A**

*Why VC and not SC?* The stolen cookie grants access to the vulnerable
application, so the confidentiality loss is the app's (`VC`). The cookie itself is
not the sensitive asset; what it unlocks is.

*Why VC:H and not VC:L?* A stolen session normally means acting as that user for
its lifetime. It drops to `VC:L` only when the session genuinely grants little: no
data worth reading, no actions worth taking. If that is the case, say so and it
comes down.

*Why is VI only Low?* A reflected payload reaches the single victim who clicks, so
any integrity impact is confined to that one user's data.

### SCENARIO 3 — Stored, no cookie exfiltration

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N
```

Default vector. `VI` is the variable metric here: it starts at `VI:L` and rises to
`VI:H` only when persistent, defacement-grade integrity impact is demonstrated
(see Notes: Defacement). `VC` is variable too: it starts at `VC:N` and rises when
the script is shown to read application data that reaches the attacker through the
victim's session — same-origin authenticated requests, no cookie exfiltration
needed (see Notes: Session-riding). `VC:H` for whole-resource or PII reads,
`VC:L` for a partial or limited kind.

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

*Why is VI Low here but None in the reflected no-cookie case?* Persistence. A
stored payload lives on the server and affects the page's rendering and data for
every loader, which is a real (if arguably limited) integrity impact. A reflected
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

*Why is VI High here but Low in Scenario 3?* Because what changed between 3 and 4
is not "a confidentiality mechanism" but the acquisition of the victim's
authenticated write access. Cookie exfiltration is an authentication-defeat
mechanism, not merely a confidentiality one: a stolen session yields both a read
capability (`VC:H`) and a write capability. Acting as the victim (post, delete,
change settings, transact) is a demonstrated integrity capability, exactly the
kind the 07-11 principle says must be earned rather than assumed, and cookie-exfil
to temporary ATO earns it. This is not double-counting the cookie; it is pricing
the read side and the write side of one stolen session on their own axes.

*Why not Critical?* `SI` stays Low. The script rewrites what a victim's browser
renders; it does not compromise the subsequent system's own integrity. Critical
needs a subsequent-system impact this lacks, for example the script reaching a
server-side privileged sink. Show that and it is a new scenario, put it in the
report.

## Notes

The reflected-to-stored integrity asymmetry (`VI:L` to `VI:H` in the cookie cases,
Scenarios 2 and 4) is deliberate: reflected compromises whoever clicks, stored
compromises whoever loads. That single metric is what separates them.

**Defacement and VI.** Stored XSS earns `VI:H` only when it demonstrates
persistent, attacker-controlled modification of content or data beyond the
transient render, that is, HTML-injection-grade defacement or action against other
users' stored data. The number of users exposed is an indicator of reach, not by
itself a basis for `VI:H` under FIRST; the integrity impact is what sets the
metric.

Self-XSS (the victim must paste the payload into their own console or a field only
they see) is not scored as XSS impact here. There is no realistic attacker path,
so it does not clear the bar on its own.

If cookie-bombing DoS is demonstrated on any of the cases, subsequent-system
availability can climb from `SA:N` to `SA:L`. For now we consider this to not
reasonably reach `SA:H` under any circumstances, as that would imply a general
unusability of the subsequent system. Credits to Kaiksi for the note on this matter.

**Session-riding and `HttpOnly`.** "No cookie exfiltration" is not "no impact."
Same-origin script executes with the victim's ambient credentials, so a
credentialed `fetch`/`XHR` reads and writes application data as the victim even
when the cookie is `HttpOnly` and cannot be read. Cookie exfiltration still
matters because it makes that access *portable and durable* — the attacker
replays the session elsewhere, after the victim leaves — but it is not what first
unlocks in-app impact. In the no-cookie scenarios, score `VC`/`VI` from what the
PoC demonstrates the script reading or writing, by magnitude: `VC:H`/`VI:H` for
whole-resource or critical reads/writes (all records of another tenant, changing
stored bank details), `VC:L`/`VI:L` for partial or limited ones. Demonstrated
only — potential in-app reach is not scored, or every XSS would be Critical. This
mirrors FIRST's expanded-impact treatment (CVE-2024-55228, Dolibarr:
`VC:H/VI:H/SC:L/SI:L`).

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
- **2026-11-11** Added a third deciding factor and the Session-riding note. `VC`/`VI`
  in the no-cookie scenarios (1 and 3) are variable by the demonstrated in-app impact
  of the executed script, because same-origin credentialed requests ride the victim's
  session even when the cookie is `HttpOnly`. Corrected the intro's second point:
  "no reachable cookie keeps it low" was wrong — a non-exfiltratable cookie caps the
  *portability* of the session, not the in-session reach of the script. No scenario
  vector changed; the baselines stand and now explicitly rise on demonstrated
  reads/writes. Departs from treating cookie-exfil as the sole elevation path;
  aligns with FIRST's expanded-impact example (CVE-2024-55228, Dolibarr).
