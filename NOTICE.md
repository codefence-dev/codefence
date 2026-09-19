# Notice on Source Availability

CodeFence is shipped as **human-readable source code**. This
is a deliberate design decision, not an accident.

## Why the source is readable

1. **Trust.** A security tool that hides its own behavior cannot be
   trusted. You can read every line before running it.

2. **Auditability.** You can verify that the tool:
   - performs **zero network calls during scans**,
   - collects **zero telemetry**,
   - writes only to `--output` and (optionally) `~/.cache/codefence/`,
   - performs one network call only for the first Pro license
     validation (Getly), then a silent refresh every 30 days,
   - never executes the code it scans.

3. **Portability.** The tool is a single Python file with zero
   third-party dependencies. You can read it, keep it, and run it
   on any system with Python 3.10 or newer.

## What this is not

Being able to read the source does **not** make this open-source
software. The license (`LICENSE.txt`) grants you the right to read,
study, and privately modify the code, but **not** to redistribute it,
resell it, bundle it, or offer it as a service.

## What you may do

- Read the source.
- Audit the source.
- Modify the source for your own personal use.
- Run it on up to 3 devices that you own.

## What you may not do

- Publish the source.
- Share it with others.
- Sell it or bundle it.
- Offer it as part of a commercial service.

If you find the tool useful and would like others to benefit, please
point them to the official purchase page rather than sharing your
copy. This keeps the project sustainable.

## A note on honesty

The vendor of this product has made a deliberate choice to be
transparent about what the tool does and does not do. The limitations
listed in `README.md` and `SECURITY.md` are real. The tool does not
claim to be a complete security solution. It claims to be a fast,
offline, pattern-based sanity checker — nothing more, nothing less.

---

*End of Notice.*
