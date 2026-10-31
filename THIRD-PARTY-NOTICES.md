# Third-party notices — GeodeCode

GeodeCode is original work. Its detection engine, mechanical collapser, non-leaking receipt,
placeholder map, SHA-256, and interface are written by GeodeForge. This file records the third-party
material it builds on.

## Gitleaks — secret-detection rule patterns (MIT)

GeodeCode's rule pack is **derived from the regular-expression signatures** published by the Gitleaks
project — https://github.com/gitleaks/gitleaks. The patterns are used **as data** (a versioned JSON
rule pack), evaluated by GeodeCode's own engine. No Gitleaks source code is included, linked, or
executed. Rules that use RE2 constructs JavaScript cannot express are not shipped (see the core spec
§6 and `bench/build-rulepack.mjs`).

**210 of the 221 upstream rules ship.** The 11 left out use scoped flag negation `(?-i:...)`, which
JavaScript regex cannot express. A further **26 are "hoisted"**: an inline `(?i)` was moved to a
whole-pattern flag, because JavaScript has no scoped flags. **That widens those rules**: text before the
original flag becomes case-insensitive too. Each hoisted rule is marked `hoisted: true` in the pack so the
widening is visible rather than silent, and the whole set was checked for false alarms against a separate
collection of documents before shipping.

Gitleaks is distributed under the MIT License:

```
MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Reference-only (NOT included)

TruffleHog (AGPL-3.0) was consulted only as research reference during design. No TruffleHog code or
rules are included in or linked by GeodeCode.

## Runtime dependencies

None. GeodeCode ships as a single self-contained HTML file with no bundled libraries, no web fonts,
and no network requests (`connect-src 'none'`). The test harnesses under `bench/` use Node's built-in
modules and Playwright (dev-only; not shipped).
