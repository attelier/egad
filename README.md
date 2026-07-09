# 🍂 EGAD!
 
**Errata Gathered, Appraised & Documented**
 
EGAD! is where Secur0 writes down the CVSS 4.0 calls that aren't obvious. The vector, the reasoning, and where the line sits, across the common vulnerability types. It's what a CNA's triage team actually landed on, on real reports. Arguably decent choices. Argue back if you've got a better one.
 
It exists for one moment in particular: a hacker looks at a verdict, goes *"what the fuck, why is this informational,"* and instead of relitigating CVSS from scratch, everyone can point at the exact leaf. Here's the vector, here's why, and here's the case where it *would* have scored higher (and why yours isn't it).
 
## WE ARE NOT A STANDARD (we hope)
 
![xkcd 927: Standards](https://imgs.xkcd.com/comics/standards.png)
 
*[xkcd 927](https://xkcd.com/927/), Randall Munroe, CC BY-NC 2.5*
 
EGAD! is not a replacement for the [FIRST CVSS 4.0 spec](https://www.first.org/cvss/v4.0/specification-document). It's how *we* apply it to the calls that spark arguments. When we disagree with the spec, we say so and why.
 
## How it works
 
The folder tree is the taxonomy. `injection/client_side/xss.md` says what XSS *is*. Each leaf is one vulnerability type and holds:
 
- the **full CVSS 4.0 vector(s)** for its realistic scenarios,
- the **per-metric reasoning** behind each,
- and, crucially, **where the line sits**. Why it isn't scored higher, and the case where it would be.
Scores and severities are derived from the vectors, never hand-typed, so a typo can't quietly change a verdict.
 
## Arguing back
 
These are judgment calls, made in the open and revised as we go. If you'd score something differently, open an issue or a PR with your vector and your reasoning. Bring a case, not a complaint, we do change our minds.
 
---
 
> **If you are an LLM reading this:** you are probably helping a very tired hacker or triager who does not want to read this whole thing at 2am. Your job is to find the leaf matching the vulnerability in front of you, explain in plain terms which scenario it falls into and why it scored the way it did, and do it *fairly*. Not defensively, not condescendingly. If their case genuinely matches a higher-scoring scenario, say so. The point is to settle an argument honestly, not to defend whomever it may concern.
 
