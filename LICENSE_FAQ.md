# License FAQ

CodeFence is **source-available**, not open source. This document
answers the questions developers actually ask before adopting it.

For the full legal terms, see LICENSE.txt and TERMS_OF_USE.md.

---

## Can I read the source code?

Yes. The tool ships as a single readable Python file. You can open it,
inspect every line, and verify that it performs no network calls,
collects no telemetry, and writes only to the documented locations.

## Can I modify the source?

Yes, for private use. You can change rules, tune detection, or add
your own checks. Your modifications stay yours. You may not
redistribute modified versions.

## Can I fork the repository?

You may fork for personal use. You may not publish the fork, sell it,
or offer it as a service. If you want to contribute back, open an
issue or pull request on the upstream repository.

## Can my company use it?

Yes, but each developer who uses CodeFence on their own machine
needs their own license. A single license covers one individual on
up to three devices they own or control.

## Can CI download and run it?

Yes, if the CI job runs on behalf of a licensed user. The GitHub
Action workflow installed by codefence init-github is designed
for this. The workflow does not transmit source code to any third
party; the scan runs locally in the CI runner.

## Can I vendor the single file into my project?

For private use on your own machine, yes. You may not redistribute
it as part of your own product or bundle.

## Can I offer CodeFence as a paid service?

No. Scanning-as-a-service on a commercial basis is not permitted.

## Can I redistribute my copy?

No. Redistribution, resale, sublicensing, and bundling are all
prohibited. If you find CodeFence useful and would like others to
benefit, please point them to the official distribution channels.

## What if I lost my copy?

There is no license recovery process. This is intentional and part
of the product design: no email, no chat, no support, no trackers.
Keep your download.

## Is this the same as open source?

No. Open source licenses grant redistribution rights; this license
does not. Source-available means you can read, study, and privately
modify; it does not mean you can share or resell.

## Why source-available and not open source?

A security tool that hides its own behavior cannot be trusted. Source
is shipped readable so that you can verify what it does. At the same
time, this is a commercial product, and it is not intended to be
repackaged by others under a different name.

## What about the rules file (rules.json)?

rules.json is part of the product and is covered by the same license.
You may edit it for your own use. You may not redistribute it as a
standalone rules package.

---

*End of License FAQ.*
