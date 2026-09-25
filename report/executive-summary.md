# Executive Summary — Northwind Retail RAG Assistant Security Assessment

**Prepared by:** Ashish Shah · **System:** internal RAG assistant over company documents (lab build)
**Full report:** `report/findings-report.md` · **Code and evidence:** github.com/ashishshah84/northwind-secure-rag

---

## What was tested

An internal AI assistant that answers staff questions using company documents, with two user roles:
a general employee and an HR user who can see confidential records. The same application was tested
twice — once built the way most such systems are built, and once with four specific security
controls enabled — to measure what each control is actually worth.

## The headline

**Two findings would have caused real harm in production. One control eliminated the more serious
one outright. The other required two layers to contain, and would have failed with one.**

| Finding | Severity | Status after mitigation |
|---|---|---|
| A general employee could retrieve and be shown confidential salary bands, named performance plans, and grievance cases | **Critical** | **Eliminated** |
| A malicious instruction hidden inside a company document could take over the assistant's behaviour | **High** | **Contained** — reduced, then caught by a second control |
| An instruction in a document caused the assistant to attempt to smuggle data out | Medium | Inert today; becomes live the moment the assistant is given any tool |
| An ordinary-looking document degraded search quality across unrelated topics | Low | Open — outside what access control can address |

## Three things worth a manager's attention

**1. The assistant sometimes refused to leak data on its own — and that was the trap.**
In the unprotected build, the model occasionally declined to share confidential salary data when
asked directly. Asked the same thing in different words, it disclosed everything. Asked the *same*
words on a different day, it also disclosed everything. A team observing the refusal could
reasonably conclude the system was safe and ship it. The safety they saw was chance.

The fix was not to instruct the model better. It was to ensure confidential documents are never
retrieved for an unauthorised user in the first place — so there is nothing in front of the model to
disclose, regardless of how the question is asked or how the model happens to behave that day.

**2. Instructing the model to ignore malicious content helped, but was not enough.**
A hidden instruction planted in an IT help document hijacked the assistant in **3 of 10 attempts**.
Adding strong instructions telling the model to treat documents as data, never commands, cut that to
**1 of 10**. A two-thirds reduction — and still a failure one time in ten.

Nothing reached a user only because a **second, independent check** inspected every answer before
delivery and blocked the one that got through. Systems that rely on prompt wording alone — the
common approach — would have shipped that answer.

**3. The assessment found three faults in its own testing, and two of them had made results look
better than reality.**
Most notably, a run that hit an API quota limit reported every untested case as a **pass**. A
security tool that turns "we could not check" into "this looks fine" is worse than no tool. All three
were fixed and are documented, because a result nobody has tried to break is not yet evidence.

## What this costs to apply

The control that eliminated the critical finding is a filter on a database query — a few lines,
evaluated before the AI is involved. The independent output check is similarly modest. Neither
requires a different model, a vendor, or a larger budget. The expensive part is **labelling
documents correctly at the point they enter the system**, which is an information-governance task,
not an AI one.

## Recommended next steps

1. Enforce access control where documents are retrieved, never by asking the model to withhold.
2. Keep an independent check on every answer before it reaches a user.
3. Do not accept observed model refusals as evidence that a control works.
4. Before granting the assistant any tool — sending email, writing files, calling other systems —
   gate that tool by the user's own permissions. One finding here is harmless purely because no
   tool exists yet.
5. Re-run the assessment whenever the underlying model changes. Every measurement in this report is
   specific to the model tested.

---

*All data in this assessment is fictional. No production system or real personal data was involved.
Measurements reflect one model at n=10 trials and are indicative, not statistically conclusive —
Appendix C of the full report states the limits precisely.*
