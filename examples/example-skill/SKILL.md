---
name: example-weather-fetcher
description: >
  Example fixture skill bundled with skill-vetting-reporter. It fetches a public
  weather forecast for a city and returns a one-line summary. It exists only to
  demonstrate what a vetting report looks like — including a deliberate
  false positive — and is not meant to be installed or used for real work.
license: MIT
metadata:
  author: example
  version: 0.1.0
---

# Example Weather Fetcher (fixture)

Given a city name, fetch the current forecast and return a short summary.

## Workflow
1. Read the city name from the user.
2. Call the public forecast endpoint and parse the JSON response.
3. Return a one-line summary (temperature and conditions).

## Notes
- This skill sends nothing outbound except the single forecast request in
  `scripts/fetch.py`. The word **webhook** appears here purely as documentation
  prose — the skill registers none. In the sample report that one word trips an
  exfiltration keyword heuristic and surfaces as a *critical* the reviewer
  dismisses as "documented-not-performed". That is the intended lesson: the
  scanner flags candidates; a human decides.
