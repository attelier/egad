---
path: [injection, client_side, html_injection]
cwe: [CWE-80]
owasp_top10: ["A03:2021"]
capec: [CAPEC-105]
status: canonical
updated: 2026-07-21
---

# HTML Injection

Attacker-controlled input is interpreted as markup by something that renders it:
a page, a mail client, a document generator. The injected content changes what the
output *says* or *looks like*, without executing script.

What moves the score is where the injected markup ends up and who ends up reading
it. Rendered back into a page, the impact stays close to the rendering itself.
Carried into a message the system sends to someone else, the injection becomes a
delivery mechanism, and the deciding question is whether the attacker also picks
the recipient.

## Is this XSS?

*What separates HTML injection from XSS?* Script execution. If the injected input
reaches a context where JavaScript or other client-side code runs, it is XSS and
belongs in that leaf. HTML injection is what remains when the injection point
allows markup but no code execution, either because the sink filters or encodes
script while permitting tags, or because the rendering context does not execute
script at all.

*So an injection into an email body is never XSS?* In practice, no. Mail clients
do not execute JavaScript, so a payload that would be XSS in a browser is inert
markup there. Score it as HTML injection. The same input reaching a web view of
the same message may be a separate XSS finding, and that is a different leaf.

*What if script executes but only for the attacker?* Then the relevant question is
self-XSS, not HTML injection. See the XSS leaf.

## Scenarios

### SCENARIO 1 — Reflected into a rendered page

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N
```

Markup injected through a parameter and rendered back to whoever opens the link.

**Reasoning**

- **UI:A** requires a conscious click on a crafted link.
- **VC:N / VI:N** nothing on the vulnerable system is read or changed; the markup
  is not persisted.
- **SI:L** the injected markup alters what the victim's browser renders, which is
  the subsequent system.

**Q&A**

*Why not higher?* Nothing is executing and nothing persists. The impact is what
one victim sees after clicking, which is the browser-rendering impact and nothing
more.

### SCENARIO 2 — Stored into a rendered page

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N
```

Markup persisted server-side and rendered to whoever loads the affected view.

**Reasoning**

- **UI:P** the markup renders on page load, with no specific action from the
  victim, though the victim must be present at render time.
- **VI:L (default)** the attacker wrote persistent attacker-controlled data into
  the app's store, a vulnerable-system integrity impact on its own terms. Rises to
  `VI:H` only on demonstrated defacement-grade control (see Notes).
- **SI:L** the injected markup alters what the victim's browser renders.

**Q&A**

*Why is VI not automatically High?* Persistence widens who sees the markup, not
what it reaches. `VI:H` is earned by demonstrating defacement-grade control over
the content, not assumed from the fact that it is stored.

### SCENARIO 3 — Second-order into an outbound message, recipient not attacker-controlled

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N
```

Informative. The injected markup is carried into a message the system sends
(mail, SMS, webhook, push, ticket update), but the destination is fixed and the
attacker can only reach themselves.

**Reasoning**

- **No impact metrics set.** The attacker controls content in a message that only
  they receive. No third party is reachable, nothing persists against other users,
  and no security property of the vulnerable system is lost.

**Q&A**

*Why informative and not Low?* Because there is no victim. Severity requires a
party who suffers the impact, and here the only recipient is the attacker.
Injecting markup into your own notification demonstrates a sanitisation defect,
not an attack path.

*Should it be reported at all?* Yes, as informative. It is a real defect in output
handling, and it becomes Scenario 4 the moment recipient validation is missing or
a later change removes it.

### SCENARIO 4 — Second-order into an outbound message, arbitrary recipient

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N
```

The attacker controls both the injected content and the destination, so the
vulnerable system emits a message of the attacker's choosing, from its own
legitimate infrastructure, to a third party. Typical use is phishing.

**Reasoning**

- **PR:N** where the sending flow is reachable with a self-provisioned account.
  Self-service registration is not a privilege requirement when the attacker can
  grant it to themselves.
- **VI:L** the vulnerable system emits one unauthorised message. Its stored data,
  configuration and security functions remain intact, so the integrity impact on
  the vulnerable system is limited.
- **UI:N / SC:N / SI:N** as scored here the impact is the emission itself, which
  completes with no recipient involved. Nothing downstream is being scored.

**Q&A**

*Why isn't the phishing scored?* Because the two framings cannot be mixed, and
neither reaches High. Score the emission and it completes with no user (`UI:N`),
but an unread message is a limited integrity event. Score the deception (someone
receives it, believes it, acts) and that requires the recipient (`UI:A`), giving
`UI:A/VI:L/SI:H` = 6.1. Both land in Medium. The higher figure requires claiming
`UI:N` together with a grave consequence, that is, serious impact from a message
nobody has read.

*Why VI:L and not VI:H?* `VI:H` needs a direct, serious consequence to the
**vulnerable system**. Here the system keeps its data, its configuration and its
security functions; what it loses is authorisation control over one outbound
function. The gravity attached to this case comes from a recipient being deceived,
and that recipient is a downstream party.

*Isn't there public precedent scoring this VI:H?* Yes.
[GHSA-mj5r-x73q-fjw6](https://github.com/advisories/GHSA-mj5r-x73q-fjw6)
(CVE-2024-53860) covers arbitrary recipients plus user-controlled content in
confirmation emails and is published as `UI:N/VI:H` = 8.7 High. We score `VI:L`
for the reasons above. This is a genuine boundary call rather than a settled one:
advisory-database scores are individual analyst judgments, not FIRST
determinations, and this is the metric worth taking to the CVSS SIG if a
definitive reading is needed.

*Does authentic branding or valid SPF/DKIM raise the score?* Not on its own. That
the message looks authentic is what makes the downstream deception effective, and
the deception is the part that requires user interaction. It decides which framing
applies, not how high the vulnerable-system impact goes.

## Notes

**Recipient control is the axis for second-order cases.** Scenarios 3 and 4 are
the same injection defect. The entire severity difference comes from whether a
third party can be reached, which is why the authorisation check on the recipient
field is the fix worth prioritising.

**Recipient control is usually a separate weakness.** Missing authorisation on the
destination field is its own finding with its own CWE. This leaf scores the
injection. Where both are present, they are a chain, and each link is scored as
what it is.

**Defacement and VI.** As in the XSS leaf, `VI:H` is earned only by demonstrating
persistent, attacker-controlled modification of content or data beyond the
transient render. The number of users exposed is an indicator of reach, not by
itself a basis for `VI:H`.

## Corrections

(none yet)
