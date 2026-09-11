---
path: [disclosure, information_exposure]
cwe: [CWE-200]
owasp_top10: ["A01:2021"]
capec: [CAPEC-116]
status: draft
updated: 2026-09-11
---

# Information Exposure

The application returns something it should not: an endpoint listing, a stack
trace, a config file, a key. Most of this class is worth nothing, which is why it
needs writing down.

`VC` is set by the kind of data disclosed. Not by its volume, not by the effort
needed to reach it, and not by who was intended to see it.

- **Kind of data.** Same test as the IDOR leaf. Ten thousand endpoint paths is ten
  thousand endpoint paths. One live key is `VC:H`.
- **Reconnaissance is not scored.** Disclosure that only reduces the cost of a
  later attack does not set an impact metric. The later attack is scored as its
  own finding.
- **An access control does not set the metric.** Its presence is evidence that the
  data may matter and is worth examining closely. It is not evidence that the data
  does matter: controls are applied out of habit, by framework default, and out of
  caution.

`VI`, `VA` and the subsequent-system metrics are `None` in every scenario here. A
disclosure does not modify data and does not act beyond the vulnerable system.

## Scenarios

### SCENARIO 1 — Nothing sensitive came out

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N
```

Informative, and the default. API documentation and specs, GraphQL introspection,
endpoint listings, version banners, a directory index of public assets, verbose
errors with no secrets in them, `.git/HEAD` returning a hash, an internal IP.
Whether any of it was behind a gate does not change this.

**Reasoning**

- **No impact metrics set.** What is disclosed describes the attack surface. The
  benefit to the attacker is reduced reconnaissance cost, which is not scored under
  any metric.

**Q&A**

*The vendor clearly did not want this public. They pulled it the moment we told
them.* Vendor reaction does not affect the metric. Material is removed for many
reasons, and intent is not one of the inputs to `VC`.

*It was behind authentication and I got past it.* That is a second finding, and
usually the more serious one. The missing check is a distinct weakness with its own
CWE and is scored separately. It does not alter `VC` here, because `VC` is set by
what was disclosed, and an endpoint list is an endpoint list whether it was gated
or served from the index page.

*It lists every endpoint in the API, including ones that recon would not have
found.* That is a reduction in reconnaissance cost. Where an endpoint behind it
proves to be broken, that endpoint is scored as its own finding. Bugcrowd rates
GraphQL Introspection Enabled at P5 informational, which is the same situation: an
interface that returns the entire schema on request.

*Version disclosure lets an attacker look up known exploits.* The known exploit is
the vulnerability. Working out which one applies is research.

*Should it be reported at all?* Yes, as informative. It is a real defect in output
handling. It moves to Scenario 2 or 3 where the disclosed material includes internal
or sensitive content.

### SCENARIO 2 — Restricted information, limited value

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
```

What came out is internal and has some value on its own: an internal hostname and
service map, a staff directory, deployment configuration, internal ticket or
project data. Not a map of the attack surface, and not sensitive either.

**Reasoning**

- **VC:L** restricted information is obtained, but the kind of loss is limited and
  causes no direct, serious loss to the vulnerable system.
- **VC not higher** the data is operational, not sensitive. Nothing here
  authenticates or identifies anybody.

**Q&A**

*6.9 for a leaked internal hostname list is very high.* It follows from the metric
definitions. `AV:N/PR:N/UI:N` with any confidentiality impact produces that score,
because there is no value between `VC:N` and `VC:L`. The step from Scenario 1 to
Scenario 2 is therefore large. State in the finding which material placed it here.

*Where is the line between 1 and 2?* Whether the disclosed material has value
independent of the attack surface it describes. A route list does not: it describes
the surface being enumerated. An internal service map does: it describes systems
that enumeration would not reveal.

### SCENARIO 3 — Sensitive information

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
```

What came out is a direct, serious loss on its own: personal data meeting a normal
SPII definition, health or financial records, private messages, identity documents,
internal business data the application exists to protect.

**Reasoning**

- **VC:H** restricted information whose disclosure presents a direct, serious
  impact. As in the IDOR leaf, partial access qualifies; the spec does not require
  that everything be divulged.
- **VI:N** no data is modified.

**Q&A**

*Where is the line between 2 and 3?* The purpose of the data. Material that
identifies a person, that a regulator treats as personal-sensitive, or that the
application exists to keep private is `VC:H`. Operational internals are `VC:L`. Name
the field that placed it, in the finding, so the call can be argued with.

*Only a handful of records came out.* Kind, not volume. See Notes.

### SCENARIO 4 — Secrets and key material

A leaked secret is not automatically the top of the scale. What decides it is what
the secret opens and whether it is live. Bugcrowd rebuilt this subcategory in VRT
1.9 for the same reason: every key was being reported as P1 and the noise was
unusable. Their split runs Intentionally Public, Sample or Invalid at P5, For
Internal Asset at P3, For Publicly Accessible Asset at P1.

**Live secret granting access to protected data or systems**

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
```

A working API key, a database password, a private key, a signing secret, a session
token. `VC:H`: the spec's own example of a High confidentiality loss is an
administrator password or a private key.

**Inert secret**

Scenario 1. Expired, revoked, a documented sample, or a key for a public asset that
grants nothing beyond what is already public. What was disclosed is a string.

**Q&A**

*The key gives full write access. Surely that is VI:H?* No. Disclosure of a
credential and use of that credential are separate links. The disclosure is scored
here and the access the credential provides is scored as its own finding. Scoring
the second link on the first is how a leaked read-only token is rated as a
takeover.

*It is a billing key, usable only to incur cost for the vendor.* No metric is set
here. We settled in the IDOR leaf that CVSS puts monetary losses
outside its scope. This is a declared divergence from VRT, which rates Pay-Per-Use
Abuse at P4: their scale prices business cost, `VC` does not. Put the cost exposure
in the finding, not in the vector.

*It is a test key in an example file.* Inert, so Scenario 1, once confirmed inert.
Keys labelled "test" in documentation are frequently live.

### SCENARIO 5 — Conditional exposure (modifier)

```
AT:P
```

The exposure depends on a condition the attacker does not control and that is not
the default: debug mode left on, a specific misconfiguration, a race on first boot.

| Base scenario | `AT:N` | `AT:P` |
| ------------- | ------ | ------ |
| 2             | 6.9    | 6.3    |
| 3 and 4       | 8.7    | 8.2    |

**Reasoning**

- **AT:P** the attack depends on a deployment condition beyond the attacker's
  control. Not for conditions that are the default, and not for conditions the
  attacker can bring about themselves.

## Notes

**Kind over volume.** Same as the IDOR leaf. The step from `VC:L` to `VC:H` is
decided by what the data is, not how many rows came out. Reach is worth stating in
the finding. It is not the metric.

**Reconnaissance is not scored.** Disclosure whose only effect is to reduce the
cost of a later attack sets no metric: endpoint enumeration, introspection, version
banners, technology fingerprinting, source maps, directory listings of otherwise
reachable files. Where the later attack succeeds, it is scored as its own finding.

**An access control does not set the metric.** Its presence warrants a closer look
at the material and nothing more. Controls are applied by habit, by framework
default and out of caution. Where the material behind one is a route list, `VC:N`
applies.

**Intent does not set the metric.** That a vendor treats data as private, marks a
repository private, or withdraws the material on notification is not an input to
`VC`.

**The disclosed material sets the metric.** VRT's Exposed Portal entries run P5 for
a protected portal, P3 for a non-admin one and P1 for an admin one: the same
exposure at three ratings, separated only by what is reachable behind it.

**The subsequent system is not reached.** Disclosure transfers data to the
attacker and performs no action beyond the vulnerable system. `SC`, `SI` and `SA`
are `None` in every scenario.

**PR is set per record.** The vectors show `PR:N` because unauthenticated exposure
is the common case. Where the data is only reachable by an authenticated caller, set
`PR:L`: 6.9 becomes 5.3, 8.7 becomes 7.1.

## Corrections

(none yet)
