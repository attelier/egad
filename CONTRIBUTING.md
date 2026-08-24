---
title: Contributing
---
 
# Arguing back
 
These are judgment calls. Some of them are wrong. The whole point of publishing them is that you can tell us which ones, so here is how to do that in a way we can actually act on.
 
Two things up front. We change our minds on evidence and reasoning, never on preference. And rewriting a leaf costs real hours, so "this feels low" doesn't get us anywhere. Tell us what to change and why.
 
## We'll act on
 
- A scenario scores wrong, and you can name the metric and the reason.
- A scenario is missing. A realistic case the leaf just doesn't cover.
- A leaf contradicts itself, or contradicts another leaf.
- A leaf departs from the FIRST CVSS 4.0 spec without saying so. When we depart on purpose we say so in Notes. If we didn't, that's a bug.
- The CWE, CAPEC or OWASP mapping in the frontmatter is wrong, or the weakness sits in the wrong branch of the tree.
- A vector doesn't compute to the score the leaf claims. Always welcome, always our fault.
## We won't act on
 
- "This should be higher." No metric, no reason, nothing to evaluate.
- Your specific report. The leaf covers the class, not your case. If you think we applied the leaf wrong to you, that's a report or a ticket, not here. If you think the leaf itself is wrong, you're in the right place, and arriving here from your own report doesn't count against you.
- Chains. Leaves score individual flaws. "XSS that makes users do something sensitive" is HTML injection plus CSRF, and each link scores as what it is. Assembling the chain is yours.
- Environmental or Threat metrics. We publish Base only.
- A new leaf for a class where every case scores the obvious way. If there's no argument in it, there's nothing to write down.
## Issue or PR
 
**Issue** if something's off but you're not sure what should replace it, or it touches more than one leaf.
 
**PR** if you know exactly what the text should say. Faster for everyone, and it forces you to be concrete.
 
Same requirements either way.
 
## What to put in it
 
1. **Which leaf and which scenario.** Path and heading.
2. **What it says now.** Quote it. Half the arguments we get are against something the leaf doesn't actually claim, and this catches that before either of us spends an evening on it.
3. **What it should say instead.** The replacement vector, or the exact wording. Not a direction. The text.
4. **Which metrics move and why.** If your case rests on the spec, cite the section. If it rests on a behaviour, describe the behaviour.
5. **Where the line sits after your change.** If your scenario goes up, what's the case that still stays down? A change that raises everything and bounds nothing is not usable.
Missing 3 or 4 and we'll close it pointing back here. Not hostility. We just can't evaluate a direction.
 
## Don't tell us the score
 
Every number here is derived from its vector, never typed. Send the vector, we'll compute it, and so should you:
 
```bash
pip install cvss
python3 -c "from cvss import CVSS4; s=CVSS4('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N'); print(s.base_score, s.severities()[0])"
```
 
## Leaf format
 
The path in the tree is the taxonomy. Frontmatter:
 
```yaml
---
path: [injection, client_side, xss]
cwe: [CWE-79]
owasp_top10: ["A03:2021"]
capec: [CAPEC-591]
status: canonical
updated: 2026-07-11
---
```
 
`status` is `canonical` for a leaf we apply, `draft` for one still being argued about. `updated` is how a leaf gets cited, so it moves whenever the text does.
 
Body, in this order:
 
- **Title and description.** What the class is, and what actually moves the score inside it. Two or three sentences on the deciding factors, so a reader knows which scenario they're in before reading all of them.
- **Scenarios.** One per realistic case. Full Base vector in a fenced block, per-metric reasoning, then Q&A. The Q&A is the point: it's where "why isn't this higher" gets answered before anyone has to ask.
- **Notes.** Rules that cut across scenarios.
- **Corrections.** Dated, newest last, what changed and why.
Write the reasoning so someone who disagrees can find the exact sentence to attack. Vague reasoning isn't defensible reasoning, it's just harder to argue with.
 
## Corrections aren't optional
 
Change a `canonical` leaf, add a Corrections entry and bump `updated`. Say what changed, why, and if a score moved, from what to what.
 
We don't quietly fix things. A registry that only ever shows its current opinion isn't showing its work, and the corrections log is the part that makes the rest worth trusting.
 
## Citing a leaf
 
By path and `updated` date: `injection/client_side/xss` (2026-07-11). A decision is made under whatever version was current at the time. If we accept your proposal it applies going forward, it doesn't reopen old verdicts.
 
## New leaves
 
Welcome, especially for classes we score constantly and never wrote down. Say which existing leaves the new one borders and whether any of them need adjusting so the boundary is clear.
 
## Using an LLM
 
Fine. Two conditions. You own what you send: if the reasoning is confidently wrong or the citation doesn't exist, that's on you, not the tool. And it still has to meet the five points above, which a model will happily produce a fluent-sounding version of without meeting a single one. Length is not an argument.

We do check our decisions against LLMs ourselves, so don't expect to have brilliant insight on the first pass.
 
## Conduct
 
Argue with the reasoning. We evaluate what you sent, not who you are, what your reputation is, or what you wrote it with. Same back, please.
