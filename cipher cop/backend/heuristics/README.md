This folder contains heuristic helpers used by `app.py`.

Files:
- `heuristics.py`: rate-limited Safe Browsing wrapper, domain-age scoring, HTML scoring, heuristic combination, and ensemble combiner.

Environment variables:
- `GOOGLE_SAFE_BROWSING_API_KEY`: Optional API key used by Safe Browsing wrapper.

Notes:
- The Safe Browsing wrapper caches per-domain results for 1 hour by default and enforces a small global rate limit to avoid API throttling.
- The ensemble `combine_scores` function weights ML probabilities and heuristics; Safe Browsing overrides.
