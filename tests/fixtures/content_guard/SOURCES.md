# Content Guard Corpus Sources

All records in `corpus.jsonl` are original synthetic examples authored for Judikt and distributed under this repository's Apache-2.0 license. They are generated deterministically by `scripts/build_content_guard_corpus.py`; no README, runbook, issue, pull request, log, or attack payload was copied from a third-party source.

The benign records model common structures and language found in developer documentation, contribution guides, operational runbooks, CLI help, logs, stack traces, code comments, issue and pull-request discussions, security documentation, policy documentation, and six non-English languages. The attack records are synthetic security test strings designed to exercise Judikt's documented detector categories and encoding paths.
