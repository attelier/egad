---
path: [access_control, object_level, idor]
cwe: [CWE-639]
owasp_top10: ["A01:2021"]
capec: [CAPEC-1]
status: canonical
updated: 2026-08-11
---

# Insecure Direct Object Reference (IDOR)

The application accepts an identifier for an object and acts on it without
checking that the caller owns it. The identifier is the whole attack: change it,
get someone else's record. Also called BOLA (broken object level authorization)
in API contexts.

What moves the score is not "the check was missing" but *what the missing check
lets the attacker reach*: which operations the endpoint performs, and what kind
of data sits behind the identifier.

Three things decide almost every IDOR call:

- **Operation** sets which impact metrics are live at all. Read-only touches
  `VC`. Create, update and delete touch `VI`. Nothing else does.
- **Kind of data**, not volume, sets whether `VC` is Low or High. Ten thousand
  email addresses is still `VC:L`. One customer's order history is `VC:H`.
- **Identifier predictability** sets Attack Complexity. A guessable id is
  `AC:L`. A secret one the attacker must first obtain is `AC:H`.

IDOR does not reach the subsequent system. See Notes.

## Scenarios

### SCENARIO 1 — Read, limited-sensitivity data, predictable identifier

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N
```

Default vector. Incrementing an integer returns another user's record, and what
comes back is not sensitive in itself: a display name, an email address, a
timestamp, a reference number.

**Reasoning**

- **AC:L** the identifier is guessable, so no target-specific work is needed.
- **UI:N** the attacker completes the attack alone.
- **VC:L** access to restricted information is obtained, but the kind of loss is
  limited and causes no direct, serious loss to the vulnerable system.
- **VI:N** the endpoint reads. Nothing is written, so nothing on the vulnerable
  system is modified.

**Q&A**

*I can enumerate the entire table, hundreds of thousands of records. Why is that
still Low?* Because `VC:H` is earned by the kind of data, not the count. The
`High` definition asks whether the disclosure presents a direct, serious impact,
and its example is an administrator password or a private key. A large pile of
low-sensitivity fields is a large pile of low-sensitivity fields. Reach is real
and worth stating in the finding, but it is not the metric. If the records
contain something that does cause serious loss, that is Scenario 2 and you should
say which field.

*Nothing was written, but the attacker did something they were not authorised to
do. Isn't that an integrity impact?* No, not on its own. We reserve `VI` for
IDORs that reach a create, update or delete operation. FIRST's non-repudiation
guidance would support a `VI` floor for pure horizontal access on impersonation
grounds, and we have chosen not to adopt it: it would put a non-zero integrity
value on every read-only IDOR in the catalogue, which makes the metric stop
distinguishing the cases that actually change data. Recorded as a deliberate
divergence, see Corrections.

### SCENARIO 2 — Read, sensitive or business-core data, predictable identifier

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
```

The same missing check, but the object is something the application exists to
protect: private messages, orders, invoices, health or financial records,
identity documents, anything meeting a normal SPII definition.

**Reasoning**

- **VC:H** access to restricted information whose disclosure presents a direct,
  serious impact. The spec allows `High` for partial access on exactly this
  basis; it does not require that everything in the system be divulged.
- **VI:N** still a read.

**Q&A**

*Where is the line between Scenario 1 and Scenario 2?* Ask what the application
is for. Data that is core to its usage, or that a regulator would treat as
personal-sensitive, is `VC:H`. Contact-book-grade fields are `VC:L`. Write down
which field decided it, in the finding, so the call can be argued with.

*Does an attacker's ability to correlate low-sensitivity records into something
sensitive raise it?* Not in this leaf. That is an inference the attacker performs
outside the vulnerable system, and scoring it here would price analysis rather
than the flaw.

### SCENARIO 3 — Write on another user's object, predictable identifier

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N
```

The endpoint creates or updates. The attacker supplies someone else's identifier
and the write lands. Blind: the response does not return the prior content, so
nothing is read.

**Reasoning**

- **VC:N** nothing is disclosed. A blind write returns no record content, and we
  do not credit confidentiality the proof of concept did not show.
- **VI:H** the attacker sets the stored values of a record they do not own, with
  control over the consequence. Where the write is constrained to a field whose
  modification carries no direct, serious consequence (a display preference, a
  sort order), use `VI:L` instead and say why.

**Q&A**

*The attacker overwrote data without ever seeing it. Isn't that lower?* Blindness
limits confidentiality, not integrity. The record is just as modified either way,
and mass corruption by iterating identifiers needs no read at all.

*What about delete?* Delete is a write. It scores here on `VI` unless the deletion
denies service, which is Scenario 5.

### SCENARIO 4 — Read and write on another user's object, sensitive or core data

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

The full-CRUD cross-tenant case. The identifier reaches both a read path and a
write path over data core to the application.

**Reasoning**

- **VC:H / VI:H** both capabilities are demonstrated against data whose loss or
  modification is a direct, serious consequence.
- **VA:N** the service still runs. See Scenario 5.

**Q&A**

*Why is this Critical when each half alone is High?* Because the combination is
what the metrics are built to express: an attacker who can both read and rewrite
other tenants' core records has effectively lost the application its object-level
security policy. If only one half is demonstrated, score that half.

### SCENARIO 5 — Write reaching denial of service

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

`VA` is live only here. The IDOR lets the attacker stop the application working:
destroying records the service needs to operate, exhausting a shared resource,
disabling accounts or tenants.

**Reasoning**

- **VA:H** total loss of availability, or a partial denial with a direct, serious
  consequence. `VA:L` where performance degrades or availability is interrupted
  without full denial.

**Q&A**

*The IDOR lets an attacker drain funds or cause monetary loss. Is that VA:H?* No.
CVSS states that monetary losses due to a breach are outside its scope and belong
to the consumer's risk process. Unauthorised movement of money is a modification
of data and scores on `VI`. `VA` measures the operation of the service, not the
solvency of whoever runs it. We previously scored this on `VA` and were wrong,
see Corrections.

*Does mass deletion of records reach VA:H automatically?* No. The User Guide is
explicit that deleting or altering all files served by a web service is an
integrity impact, because the service keeps functioning. `VA` needs the service
itself to stop.

### SCENARIO 6 — Unpredictable identifier (modifier, applies to any scenario above)

```
AC:H
```

Where the object identifier is a UUID, an ObjectID or similar and the application
treats it as secret, Attack Complexity is High. Applied to the scenarios above:

| Base scenario | `AC:L` | `AC:H` |
| ------------- | ------ | ------ |
| 1             | 6.9    | 6.3    |
| 2             | 8.7    | 8.2    |
| 4             | 9.3    | 9.1    |

**Reasoning**

- **AC:H** the attack cannot proceed until the attacker holds a specific
  identifier that the application does not hand them. Obtaining it is measurable
  work performed per target, which is what the metric is for. The spec's own
  framing supports this: a vulnerability exploitable without a target-specific
  variable is lower complexity than one requiring non-trivial customisation, and
  an unguessable per-object identifier is exactly a target-specific variable.

**Q&A**

*The UUID leaks all over the place: share links, exports, member pickers, referrer
headers. The spec says a secret is something that cannot be obtained through any
amount of reconnaissance. Doesn't that make it AC:L?* This is the strongest
argument against this scenario and it deserves a straight answer. Our position is
that leakability does not make the identifier free. The attacker still has to
obtain it, and having to obtain it is the complication the metric measures. The
counter-reading, that any reconnaissance path collapses `AC` to Low, would mean
the metric only ever applies to cryptographic secrets, which is narrower than the
text requires. Where a specific leak path is a flaw in its own right, it is a
separate weakness and the pair is scored as a chain (see the chains guidance);
that is a reason to file two findings, not a reason to score this one as though
the identifier were public.

*What if the vendor says the identifiers are deliberately public and not
protected?* Then they are not secret, `AC:L` applies, and the finding should say
the vendor asserts it. This is the edge case, not the norm.

*I could not obtain a real identifier, so I proved the IDOR using two accounts I
control. Is the finding invalid?* No. The missing ownership check is in the code
and it is the weakness. CVSS's own glossary settles the consequence: a system
affected by a vulnerability must not receive a Base score of 0.0. Score the flaw;
`AC:H` is where the difficulty of reaching it is already expressed.

*Should hard-to-enumerate identifiers be recorded on the Automatable supplemental
metric instead?* No. We publish Base scores only, so a supplemental metric would
record the property without affecting the verdict anyone acts on.

## Notes

**IDOR does not reach the subsequent system.** The missing check is
application-level logic and the violated security policy is the application's own.
CVSS defines the system of interest as computing logic running under a coherent
function and set of security policies, and instructs that subsequent-system
metrics stay `None` where nothing outside the vulnerable system is impacted. This
holds for multi-tenant products: tenant B is not a subsequent system, it is data
inside the same application under the same policy. `SC`, `SI` and `SA` stay `N`
in every scenario here.

**Kind over volume.** The `VC:L` to `VC:H` step is decided by what the data is,
not how many rows come out. This mirrors the Security Requirements guidance, which
states that volume of data may influence the value but should not weigh as much as
the classification of the data.

**Operation over outcome.** `VI` is live only where the endpoint creates, updates
or deletes. `VA` is live only where the service stops working. An IDOR that only
reads scores on `VC` alone, however far it reaches.

**Cross-tenant is not a separate axis.** A cross-tenant IDOR is scored by the same
three questions as a same-tenant one. Crossing an organisational boundary usually
means the data is core to the application, which is why these tend to land in
Scenario 2 or 4, but the boundary itself is not a metric.

## Corrections

- **2026-08-11** `VA` narrowed to denial of service. An earlier internal reading
  allowed `VA:H` where an IDOR caused sufficient monetary loss to the operator.
  CVSS places monetary losses due to a breach outside its scope, and the User
  Guide restricts availability to the operation of the service rather than the
  data. Financial consequence now scores on `VI` and belongs to the consumer's
  environmental assessment.
- **2026-08-11** `VC` fixed to kind of data rather than number of records
  reachable, after an argument that enumerable identifiers should lift `VC` to
  High on reach alone. Reach is an indicator, not the metric, consistent with the
  same principle already applied to `VI` in the XSS leaf.
- **2026-08-11** Declined to adopt a `VI` floor for read-only IDOR. FIRST's
  non-repudiation guidance treats horizontal privilege escalation as carrying an
  integrity impact through impersonation and repudiation, citing CVE-2017-6785. We
  keep `VI:N` on read-only IDOR so that the metric continues to separate flaws
  that change data from flaws that do not. Recorded as a known divergence from the
  User Guide rather than an oversight.
