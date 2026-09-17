# Lessons Learned

Internal engineering notes. Not shipped in the product ZIP.

This file records concrete lessons from building CodeFence. Each entry
includes the situation, the mistake, the fix, and a rule for the future.

---

## 1. Read the official docs before debugging

**Situation:** Six hours spent trying to make the PyPI project page
show the package README. Dozens of rebuilds, `pyproject.toml`
rewrites, setuptools version pinning, Metadata-Version adjustments.

**Mistake:** Debugging by trial and error instead of reading the PyPI
Upload API documentation, which specifies exactly which multipart
form fields are required.

**Fix:** The upload request must include `summary`, `description`,
and `description_content_type` as separate form fields. `curl`
without these fields uploads the artifact but leaves the release
metadata empty. `twine` handles this transparently; direct `curl`
does not.

**Rule:** When integrating with an external API or tool, read the
official docs first. Debug only after the documented contract is
understood.

---

## 2. Identify the failing layer before touching code

**Situation:** Same PyPI issue. Changes were being made to the build
layer (pyproject.toml, setuptools versions), but the failure was in
the upload layer.

**Mistake:** Assumed that METADATA inside the wheel automatically
becomes project metadata on PyPI. This assumption was never verified.

**Fix:** Confirmed with `unzip -p` that METADATA was correct inside
the wheel, then confirmed with `curl https://pypi.org/pypi/.../json`
that PyPI was not reading it. The gap was the upload, not the build.

**Rule:** A system has layers (build, upload, install, runtime).
Identify which layer is failing before changing anything.

---

## 3. Set a time limit for solo debugging

**Situation:** Six hours on a single problem.

**Mistake:** Kept trying "one more thing" without escalating.

**Fix:** After receiving consultation from four AI systems, the fix
took 15 minutes.

**Rule:** If a problem resists for 30 minutes of focused effort,
stop and consult. Multiple independent perspectives converge faster
than one long attempt.

---

## 4. Verify assumptions explicitly

**Situation:** Assumed `pip install codefence` would find
`rules.json` because the file was listed in `pyproject.toml`.

**Mistake:** Never tested the fresh install without `--rules`.

**Fix:** Added a multi-path search (`_default_rules_path`) that
checks source checkout, `sys.prefix`, `share/codefence/`, working
directory, and user config directories. Also switched from
`package-data` (which doesn't apply to `py-modules`) to `data-files`.

**Rule:** Every implicit assumption is a future bug. Make it
explicit; test it on a clean environment.

---

## 5. Agreement between independent consultants is a strong signal

**Situation:** Four AI systems (Grok, Perplexity, ChatGPT, Claude)
were asked the same technical question without cross-contamination.
All four independently identified the same root cause.

**Fix:** The solution each proposed was tested and worked on the
first attempt.

**Rule:** When two or more independent experts converge on the same
diagnosis, the diagnosis is probably correct. Treat consensus as
high-confidence signal, not as something to re-litigate.

---

## 6. Design audits benefit from multiple perspectives

**Situation:** A design review was requested for the CLI and HTML
interfaces. Four AI systems each reviewed independently.

**Fix:** All four identified the same top issues:
- The banner box on every invocation wastes space
- The inline fix diff does not scale beyond a handful of findings
- The HTML dashboard style reads as "generic AI-generated"

**Rule:** For subjective design decisions, collect multiple
independent reviews. Use the intersection as the priority list.

---

## 7. Security tokens in chat are permanent leaks

**Situation:** A GitHub Personal Access Token was accidentally
pasted into the chat as a command.

**Fix:** The token was immediately revoked and replaced. After
that, tokens were stored only in the password manager and pasted
directly into the terminal prompt.

**Rule:** Never paste secrets into chat, logs, or messages. Only
paste into prompted fields in the target application.

---

*End of LESSONS.md*
