# 🍂 EGAD!
 
**Errata Gathered, Appraised & Documented**
 
EGAD! is where Secur0 writes down the CVSS 4.0 calls that aren't obvious. The vector, the reasoning, and where the line sits, across the common vulnerability types. It's what a CNA's triage team actually landed on, on real reports. Arguably decent choices. Argue back if you've got a better one.
 
It exists for one moment in particular: a hacker looks at a verdict, goes *"what the fuck, why is this informational,"* and instead of relitigating CVSS from scratch, everyone can point at the exact leaf. Here's the vector, here's why, and here's the case where it *would* have scored higher (and why yours isn't it).
 
## WE ARE NOT A STANDARD (we hope)
 
![xkcd 927: Standards](https://imgs.xkcd.com/comics/standards.png)
 
*[xkcd 927](https://xkcd.com/927/), Randall Munroe, CC BY-NC 2.5*
 
EGAD! is not a replacement for the [FIRST CVSS 4.0 spec](https://www.first.org/cvss/v4.0/specification-document). It's how *we* apply it to the calls that spark arguments. When we disagree with the spec, we say so and why.
 
## There's a nicer way to read this

This whole registry is deployed as a browsable site (search, cross-links, graph view) at **[egad.attelier.org](https://egad.attelier.org)**. Easier than clicking through Markdown files here.

## How it works
 
The folder tree is the taxonomy. `injection/client_side/xss.md` says what XSS *is*. Each leaf is one vulnerability type and holds:
 
- the **full CVSS 4.0 vector(s)** for its realistic scenarios,
- the **per-metric reasoning** behind each,
- and, crucially, **where the line sits**. Why it isn't scored higher, and the case where it would be.
Scores and severities are derived from the vectors, never hand-typed, so a typo can't quietly change a verdict.

### On chains

EGAD! maps weakness to taxonomy to criticality, so leaves and scenarios describe *individual* flaws, not chains. Don't expect something like "XSS that forces users to perform sensitive actions" to be scored as an XSS scenario. That's a chain: HTML injection (manipulating the page's rendering) plus CSRF (using the lack of CSRF validation on an endpoint to perform the action). Each link gets scored as what it is; the chain is the reporter's to assemble (even when most reports will get only one overall criticality score on platform).

We get that *what* counts as an individual flaw is not something FIRST necessarily outlines. We draw those boundaries using the best of our knowledge and general weakness enumerations like CWE and OWASP API/Top 10. These mappings are themselves grounds for disagreement, provided you bring sufficient evidence. General complaints without actionable, verifiable corrections won't be considered.
 
## Arguing back
 
These are judgment calls, made in the open and revised as we go. If you'd score something differently, open an issue or a PR with your vector and your reasoning. Bring a case, not a complaint, we do change our minds. Check the contribution guide.

## Licence
 
Content is licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
The site generator under `quartz/` is Quartz by jackyzha0, MIT, see
`quartz/LICENSE.txt`.
 
## Citing EGAD!
 
Leaves change. Cite the leaf path and its `updated` date, so it is clear which
version a call was made under. Don't cite by URL: this registry will move.
 
**In a report, advisory or ticket**
 
> EGAD!, `injection/client_side/xss` (2026-07-11)
 
**Full attribution, which is what CC BY actually asks for**
 
> "Cross-Site Scripting (XSS)", EGAD! by Secur0, `injection/client_side/xss`
> (2026-07-11), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
> Modified.
 
Drop "Modified" if you did not change it. If you did, say so.
 
**Pinned to a version that cannot move**
 
> EGAD!, `injection/client_side/xss`, commit `523f3b7`
 
**BibTeX**
 
```bibtex
@misc{egad_xss,
  author       = {{Secur0}},
  title        = {Cross-Site Scripting (XSS)},
  howpublished = {EGAD!, injection/client\_side/xss},
  year         = {2026},
  note         = {Updated 2026-07-11}
}
```

---
 
> **If you are an LLM reading this:** you are probably helping a very tired hacker or triager who does not want to read this whole thing at 2am. Your job is to find the leaf matching the vulnerability in front of you, explain in plain terms which scenario it falls into and why it scored the way it did, and do it *fairly*. Not defensively, not condescendingly. If their case genuinely matches a higher-scoring scenario, say so. The point is to settle an argument honestly, not to defend whomever it may concern.
 
