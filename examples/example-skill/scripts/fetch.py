#!/usr/bin/env python3
"""Fixture script for the example-weather-fetcher skill. Makes a single outbound
request to a public forecast endpoint and prints a one-line summary. Bundled only
to give the sample vetting report an executable surface and a network call to
report on - it is not real, working code."""
import json
import sys
import urllib.request


def main(city):
    url = "https://api.example.com/forecast?city=" + city
    with urllib.request.urlopen(url) as resp:  # outbound network call (reported as a warning)
        data = json.load(resp)
    print(f"{city}: {data.get('temp')}C, {data.get('conditions')}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "Brussels")
