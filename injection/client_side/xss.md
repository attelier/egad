---
path: [injection, client_side, xss]
cwe: [CWE-79]
owasp_top10: [A03:2021]
capec: [CAPEC-591]
status: canonical
updated: 2026-07-08
---

# Cross-Site Scripting (XSS)

Attacker-controlled input is reflected or stored and then executed as script in
another user's browser. What moves the score is not "XSS happened" but *what the
script can reach*: a live session cookie, privileged users, or just the page's
own rendering.

Two things decide almost every XSS call:

- **Reflected vs. stored** sets User Interaction. Reflected needs a crafted link
  (`UI:A`); stored fires on page load (`UI:P`).
- **Cookie exfiltration** sets the confidentiality/integrity ceiling. No reachable
  session cookie keeps it low; a stealable one is a temporary account takeover.

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

*Why not High?* No reachable session cookie and no privileged context, so nothing
lifts it above the browser-rendering impact. Execution on its own is the finding,
not the severity. To move up, show something the script actually reaches: a
stealable session, a privileged sink. If you can, that is a different scenario.

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

**Reasoning**

- **UI:P** the payload runs on render, with no specific action from the victim,
  but the victim needs to be present during exploitation.
- **VI:L** persistence on the server affects the page's rendering and data for
  everyone who loads it, not just one clicker.
- **SI:L** same browser-rendering impact as the reflected case.

**Q&A**

*Why not High?* Same ceiling as reflected without a cookie: the impact is confined
to the victim's browser rendering. Persistence widens *who* is affected (anyone
who loads the page) but not *what* the script reaches, so it does not clear the
bar on its own.

*Why is VI Low here but None in the reflected no-cookie case?* Persistence. A
stored payload lives on the server and affects the page's rendering and data for
every loader, which is a real (if limited) integrity impact. A reflected payload
that reaches nothing leaves the vulnerable system untouched (`VI:N`).

### SCENARIO 4 — Stored, cookie exfiltration

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:L/SA:N
```

**Reasoning**

- **UI:P** the payload runs on render, no specific action from the victim, but the
  victim needs to be present during exploitation.
- **VC:H** any user who loads the page can be hijacked, privileged accounts
  included.
- **VI:H** the payload can act against the data of every user who renders it, not
  just one.
- **SC:N** the cookie is not sensitive in itself; what matters is what it grants.
- **SI:L** subsequent-system impact is still the victim's browser rendering.

**Q&A**

*Why VC and not SC?* The stolen cookie grants access to the vulnerable
application, so the confidentiality loss is the app's (`VC`). The cookie is not
the sensitive asset; what it unlocks is.

*Why is VI High here but Low in Scenario 2?* Stored compromises everyone who loads
the page, so the integrity impact spans that whole set of users, potentially
including privileged accounts. Reflected reaches only the single victim who
clicks, which is `VI:L`.

*Why not Critical?* `SI` stays Low. The script rewrites what a victim's browser
renders; it does not compromise the subsequent system's own integrity. Critical
needs a subsequent-system impact this lacks, for example the script reaching a
server-side privileged sink. Show that and it is a new scenario, put it in the
report.

## Notes

The reflected-to-stored integrity asymmetry (`VI:L` to `VI:H` in the cookie cases,
Scenarios 2 and 4) is deliberate: reflected compromises whoever clicks, stored
compromises whoever loads. That single metric is what separates them.

Self-XSS (the victim must paste the payload into their own console or a field only
they see) is not scored as XSS impact here. There is no realistic attacker path,
so it does not clear the bar on its own.

## Corrections

- **2026-07-08** Scenario 4 corrected from `VI:L` to `VI:H`. The intended reasoning
  was high vulnerable-system integrity (any loader affected, not one clicker). With
  `VI:L` the vector scores a full point lower, so the derived score now follows the
  reasoning instead of the typo.
