### owasp-java

Source: https://github.com/OWASP-Benchmark/BenchmarkJava/archive/c6717ea295433deba1b20bb3127614833d005462.tar.gz (expectedresults-1.2.csv). Licence: GPL-2.0. 2740 labelled cases (1415 positive, 1325 negative); match rule: a finding in the test case's file with the test case's CWE (OWASP Benchmark rule).

| Tool | Version | Status | Time (s) | Findings | Unrelated | TP | FP | FN | TN | Precision | Recall (TPR) | FPR | F1 | Score (TPR−FPR) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| opengrep | 2.0.0 | succeeded | 3.7 | 449 | 2 | 241 | 206 | 1174 | 1119 | 53.9% | 17.0% | 15.6% | 25.9% | +1.5 |
| semgrep-ce | 1.172.0 | succeeded | 12.7 | 449 | 2 | 241 | 206 | 1174 | 1119 | 53.9% | 17.0% | 15.6% | 25.9% | +1.5 |
| bearer | 2.1.3 | succeeded | 39.1 | 2194 | 17 | 980 | 382 | 435 | 943 | 72.0% | 69.3% | 28.8% | 70.6% | +40.4 |
| **PATHOS combined (merged by fingerprint)** | — | succeeded | 55.4 | 3092 | 21 | 1033 | 434 | 382 | 891 | 70.4% | 73.0% | 32.8% | 71.7% | +40.2 |

Mean over the categories with positive and negative cases (the OWASP Benchmark scorecard's summary; each category weighs the same):

| Tool | Categories | Mean TPR | Mean FPR | Mean score |
|---|---:|---:|---:|---:|
| opengrep | 11 | 8.1% | 8.1% | +0.0 |
| semgrep-ce | 11 | 8.1% | 8.1% | +0.0 |
| bearer | 11 | 70.0% | 32.0% | +38.1 |
| combined | 11 | 71.8% | 34.0% | +37.8 |

Any finding in the test case's file, whatever its CWE (for comparison; not the OWASP rule):

| Tool | TP | FP | Recall (TPR) | FPR | Score |
|---|---:|---:|---:|---:|---:|
| opengrep | 241 | 206 | 17.0% | 15.6% | +1.5 |
| semgrep-ce | 241 | 206 | 17.0% | 15.6% | +1.5 |
| bearer | 1060 | 722 | 74.9% | 54.5% | +20.4 |
| combined | 1113 | 774 | 78.7% | 58.4% | +20.2 |

Per category, recall (TPR) / false positive rate:

| Category | Positive | Negative | opengrep | semgrep-ce | bearer | combined |
|---|---:|---:|---|---|---|---|
| cmdi | 126 | 125 | 0.0% / 0.0% | 0.0% / 0.0% | 47.6% / 32.8% | 47.6% / 32.8% |
| crypto | 130 | 116 | 0.0% / 0.0% | 0.0% / 0.0% | 100.0% / 23.3% | 100.0% / 23.3% |
| hash | 129 | 107 | 0.0% / 0.0% | 0.0% / 0.0% | 69.0% / 0.0% | 69.0% / 0.0% |
| ldapi | 27 | 32 | 0.0% / 0.0% | 0.0% / 0.0% | 55.6% / 37.5% | 55.6% / 37.5% |
| pathtraver | 133 | 135 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% |
| securecookie | 36 | 31 | 0.0% / 0.0% | 0.0% / 0.0% | 100.0% / 0.0% | 100.0% / 0.0% |
| sqli | 272 | 232 | 88.6% / 88.8% | 88.6% / 88.8% | 78.7% / 73.7% | 98.2% / 96.1% |
| trustbound | 83 | 43 | 0.0% / 0.0% | 0.0% / 0.0% | 94.0% / 90.7% | 94.0% / 90.7% |
| weakrand | 218 | 275 | 0.0% / 0.0% | 0.0% / 0.0% | 100.0% / 0.0% | 100.0% / 0.0% |
| xpathi | 15 | 20 | 0.0% / 0.0% | 0.0% / 0.0% | 73.3% / 55.0% | 73.3% / 55.0% |
| xss | 246 | 209 | 0.0% / 0.0% | 0.0% / 0.0% | 52.4% / 38.8% | 52.4% / 38.8% |

### owasp-python

Source: https://github.com/OWASP-Benchmark/BenchmarkPython/archive/f1291485808b66e20ddb6b01b10dc71b3df8c8ba.tar.gz (expectedresults-0.1.csv). Licence: GPL-3.0. 1230 labelled cases (452 positive, 778 negative); match rule: a finding in the test case's file with the test case's CWE (OWASP Benchmark rule).

| Tool | Version | Status | Time (s) | Findings | Unrelated | TP | FP | FN | TN | Precision | Recall (TPR) | FPR | F1 | Score (TPR−FPR) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| opengrep | 2.0.0 | succeeded | 1.9 | 184 | 0 | 101 | 30 | 351 | 748 | 77.1% | 22.4% | 3.9% | 34.6% | +18.5 |
| semgrep-ce | 1.172.0 | succeeded | 8.5 | 184 | 0 | 101 | 30 | 351 | 748 | 77.1% | 22.4% | 3.9% | 34.6% | +18.5 |
| bearer | 2.1.3 | succeeded | 31.9 | 314 | 3 | 84 | 7 | 368 | 771 | 92.3% | 18.6% | 0.9% | 30.9% | +17.7 |
| bandit | 1.9.4 | succeeded | 4.5 | 536 | 3 | 108 | 25 | 344 | 753 | 81.2% | 23.9% | 3.2% | 36.9% | +20.7 |
| ruff | 0.17.5 | succeeded | 0.1 | 348 | 2 | 85 | 14 | 367 | 764 | 85.9% | 18.8% | 1.8% | 30.9% | +17.0 |
| **PATHOS combined (merged by fingerprint)** | — | succeeded | 46.8 | 1566 | 8 | 184 | 30 | 268 | 748 | 86.0% | 40.7% | 3.9% | 55.3% | +36.9 |

Mean over the categories with positive and negative cases (the OWASP Benchmark scorecard's summary; each category weighs the same):

| Tool | Categories | Mean TPR | Mean FPR | Mean score |
|---|---:|---:|---:|---:|
| opengrep | 14 | 25.3% | 16.7% | +8.6 |
| semgrep-ce | 14 | 25.3% | 16.7% | +8.6 |
| bearer | 14 | 12.3% | 1.4% | +10.9 |
| bandit | 14 | 25.0% | 15.7% | +9.3 |
| ruff | 14 | 23.3% | 8.5% | +14.8 |
| combined | 14 | 34.1% | 16.7% | +17.5 |

Any finding in the test case's file, whatever its CWE (for comparison; not the OWASP rule):

| Tool | TP | FP | Recall (TPR) | FPR | Score |
|---|---:|---:|---:|---:|---:|
| opengrep | 121 | 63 | 26.8% | 8.1% | +18.7 |
| semgrep-ce | 121 | 63 | 26.8% | 8.1% | +18.7 |
| bearer | 198 | 98 | 43.8% | 12.6% | +31.2 |
| bandit | 224 | 128 | 49.6% | 16.4% | +33.1 |
| ruff | 201 | 117 | 44.5% | 15.0% | +29.4 |
| combined | 260 | 192 | 57.5% | 24.7% | +32.8 |

Per category, recall (TPR) / false positive rate:

| Category | Positive | Negative | opengrep | semgrep-ce | bearer | bandit | ruff | combined |
|---|---:|---:|---|---|---|---|---|---|
| cmdi | 13 | 7 | 53.8% / 100.0% | 53.8% / 100.0% | 0.0% / 0.0% | 100.0% / 100.0% | 100.0% / 100.0% | 100.0% / 100.0% |
| codeinj | 20 | 33 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% |
| deserialization | 18 | 36 | 100.0% / 33.3% | 100.0% / 33.3% | 72.2% / 19.4% | 72.2% / 19.4% | 72.2% / 19.4% | 100.0% / 33.3% |
| hash | 71 | 80 | 100.0% / 0.0% | 100.0% / 0.0% | 100.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 100.0% / 0.0% |
| ldapi | 16 | 13 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% |
| pathtraver | 65 | 103 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% |
| redirect | 13 | 21 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% |
| securecookie | 24 | 15 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% |
| sqli | 5 | 11 | 100.0% / 100.0% | 100.0% / 100.0% | 0.0% / 0.0% | 100.0% / 100.0% | 100.0% / 0.0% | 100.0% / 100.0% |
| trustbound | 18 | 19 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% |
| weakrand | 99 | 227 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 77.8% / 0.0% | 54.5% / 0.0% | 77.8% / 0.0% |
| xpathi | 51 | 135 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% |
| xss | 31 | 58 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% |
| xxe | 8 | 20 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% |

### secrets-selfmade

Source: generated by pathos-bench gen-secrets, seed 20261119. Licence: Apache-2.0 (PATHOS; generated, self-made). 103 labelled cases (64 positive, 39 negative); match rule: any secrets finding in the case's file.

| Tool | Version | Status | Time (s) | Findings | Unrelated | TP | FP | FN | TN | Precision | Recall (TPR) | FPR | F1 | Score (TPR−FPR) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gitleaks | 8.30.1 | succeeded | 0.1 | 60 | 0 | 56 | 0 | 8 | 39 | 100.0% | 87.5% | 0.0% | 93.3% | +87.5 |
| trufflehog | 3.99.9 | succeeded | 1.8 | 40 | 0 | 40 | 0 | 24 | 39 | 100.0% | 62.5% | 0.0% | 76.9% | +62.5 |
| kingfisher | 2.19.1 | succeeded | 6.7 | 44 | 0 | 44 | 0 | 20 | 39 | 100.0% | 68.8% | 0.0% | 81.5% | +68.8 |
| detect-secrets | 1.5.0 | succeeded | 1.4 | 89 | 0 | 64 | 12 | 0 | 27 | 84.2% | 100.0% | 30.8% | 91.4% | +69.2 |
| talisman | 1.37.0 | succeeded | 1.0 | 406 | 0 | 52 | 33 | 12 | 6 | 61.2% | 81.2% | 84.6% | 69.8% | -3.4 |
| **PATHOS combined (merged by fingerprint)** | — | succeeded | 10.9 | 639 | 0 | 64 | 33 | 0 | 6 | 66.0% | 100.0% | 84.6% | 79.5% | +15.4 |

Per category, recall (TPR) / false positive rate:

| Category | Positive | Negative | gitleaks | trufflehog | kingfisher | detect-secrets | talisman | combined |
|---|---:|---:|---|---|---|---|---|---|
| aws-access-key | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| aws-documentation-example | 0 | 2 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 100.0% | n/a / 100.0% | n/a / 100.0% |
| azure-storage-key | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| data-uri | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 100.0% | n/a / 100.0% |
| env-reference | 0 | 4 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 50.0% | n/a / 50.0% |
| function-call | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 100.0% | n/a / 100.0% |
| generic-password | 4 | 0 | 0.0% / n/a | 0.0% / n/a | 0.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| git-commit-id | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 66.7% | n/a / 100.0% | n/a / 100.0% |
| github-fine-grained-token | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| github-token | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 75.0% / n/a | 100.0% / n/a |
| gitlab-token | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 50.0% / n/a | 100.0% / n/a |
| google-api-key | 4 | 0 | 100.0% / n/a | 0.0% / n/a | 100.0% / n/a | 100.0% / n/a | 50.0% / n/a | 100.0% / n/a |
| jwt | 4 | 0 | 100.0% / n/a | 0.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| lockfile-integrity | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 66.7% | n/a / 100.0% | n/a / 100.0% |
| npm-token | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 75.0% / n/a | 100.0% / n/a |
| placeholder | 0 | 4 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 75.0% | n/a / 75.0% |
| postgres-url-password | 4 | 0 | 0.0% / n/a | 100.0% / n/a | 0.0% / n/a | 100.0% / n/a | 50.0% / n/a | 100.0% / n/a |
| private-key-pkcs8 | 4 | 0 | 100.0% / n/a | 0.0% / n/a | 0.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| private-key-rsa | 4 | 0 | 100.0% / n/a | 0.0% / n/a | 0.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| public-key | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 100.0% | n/a / 100.0% |
| public-key-pem | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 100.0% | n/a / 100.0% |
| sendgrid-api-key | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| sha256-hash | 0 | 4 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 75.0% | n/a / 100.0% | n/a / 100.0% |
| slack-bot-token | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 50.0% / n/a | 100.0% / n/a |
| stripe-secret-key | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 50.0% / n/a | 100.0% / n/a |
| twilio-api-key | 4 | 0 | 100.0% / n/a | 0.0% / n/a | 0.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| ui-text | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 100.0% | n/a / 100.0% | n/a / 100.0% |
| uuid | 0 | 4 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 25.0% | n/a / 25.0% |

### secrets-selfmade without Talisman

Source: generated by pathos-bench gen-secrets, seed 20261119. Licence: Apache-2.0 (PATHOS; generated, self-made). 103 labelled cases (64 positive, 39 negative); match rule: any secrets finding in the case's file.

| Tool | Version | Status | Time (s) | Findings | Unrelated | TP | FP | FN | TN | Precision | Recall (TPR) | FPR | F1 | Score (TPR−FPR) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| gitleaks | 8.30.1 | succeeded | 0.1 | 60 | 0 | 56 | 0 | 8 | 39 | 100.0% | 87.5% | 0.0% | 93.3% | +87.5 |
| trufflehog | 3.99.9 | succeeded | 1.8 | 40 | 0 | 40 | 0 | 24 | 39 | 100.0% | 62.5% | 0.0% | 76.9% | +62.5 |
| kingfisher | 2.19.1 | succeeded | 6.7 | 44 | 0 | 44 | 0 | 20 | 39 | 100.0% | 68.8% | 0.0% | 81.5% | +68.8 |
| detect-secrets | 1.5.0 | succeeded | 1.4 | 89 | 0 | 64 | 12 | 0 | 27 | 84.2% | 100.0% | 30.8% | 91.4% | +69.2 |
| **PATHOS combined (merged by fingerprint)** | — | succeeded | 10.0 | 233 | 0 | 64 | 12 | 0 | 27 | 84.2% | 100.0% | 30.8% | 91.4% | +69.2 |

Per category, recall (TPR) / false positive rate:

| Category | Positive | Negative | gitleaks | trufflehog | kingfisher | detect-secrets | combined |
|---|---:|---:|---|---|---|---|---|
| aws-access-key | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| aws-documentation-example | 0 | 2 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 100.0% | n/a / 100.0% |
| azure-storage-key | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| data-uri | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% |
| env-reference | 0 | 4 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% |
| function-call | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% |
| generic-password | 4 | 0 | 0.0% / n/a | 0.0% / n/a | 0.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| git-commit-id | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 66.7% | n/a / 66.7% |
| github-fine-grained-token | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| github-token | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| gitlab-token | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| google-api-key | 4 | 0 | 100.0% / n/a | 0.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| jwt | 4 | 0 | 100.0% / n/a | 0.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| lockfile-integrity | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 66.7% | n/a / 66.7% |
| npm-token | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| placeholder | 0 | 4 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% |
| postgres-url-password | 4 | 0 | 0.0% / n/a | 100.0% / n/a | 0.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| private-key-pkcs8 | 4 | 0 | 100.0% / n/a | 0.0% / n/a | 0.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| private-key-rsa | 4 | 0 | 100.0% / n/a | 0.0% / n/a | 0.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| public-key | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% |
| public-key-pem | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% |
| sendgrid-api-key | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| sha256-hash | 0 | 4 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 75.0% | n/a / 75.0% |
| slack-bot-token | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| stripe-secret-key | 4 | 0 | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| twilio-api-key | 4 | 0 | 100.0% / n/a | 0.0% / n/a | 0.0% / n/a | 100.0% / n/a | 100.0% / n/a |
| ui-text | 0 | 3 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 100.0% | n/a / 100.0% |
| uuid | 0 | 4 | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% | n/a / 0.0% |

### sca-pinned-versions

Source: PATHOS benchmarks/suites/sca (self-made projects); answer key from api.osv.dev on 2026-11-19. Licence: Apache-2.0 (PATHOS; self-made). 70 labelled cases (57 positive, 13 negative); match rule: a dependency finding for the case's package, in its directory, with one of the vulnerability's IDs (CVE, GHSA, GO, PYSEC).

| Tool | Version | Status | Time (s) | Findings | Unrelated | TP | FP | FN | TN | Precision | Recall (TPR) | FPR | F1 | Score (TPR−FPR) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| trivy-fs | 0.76.2 | succeeded | 120.4 | 60 | 2 | 57 | 0 | 0 | 13 | 100.0% | 100.0% | 0.0% | 100.0% | +100.0 |
| grype | 0.121.3 | succeeded | 97.9 | 57 | 0 | 57 | 0 | 0 | 13 | 100.0% | 100.0% | 0.0% | 100.0% | +100.0 |
| osv-scanner | 2.7.1 | succeeded | 9.5 | 112 | 2 | 57 | 0 | 0 | 13 | 100.0% | 100.0% | 0.0% | 100.0% | +100.0 |
| pip-audit | 2.10.1 | succeeded | 4.5 | 58 | 0 | 31 | 0 | 26 | 13 | 100.0% | 54.4% | 0.0% | 70.5% | +54.4 |
| npm-audit | 12.2.3 | succeeded | 2.2 | 8 | 0 | 8 | 0 | 49 | 13 | 100.0% | 14.0% | 0.0% | 24.6% | +14.0 |
| govulncheck | 1.10.0 | succeeded | 24.4 | 6 | 0 | 6 | 0 | 51 | 13 | 100.0% | 10.5% | 0.0% | 19.1% | +10.5 |
| **PATHOS combined (merged by fingerprint)** | — | succeeded | 258.9 | 68 | 2 | 57 | 0 | 0 | 13 | 100.0% | 100.0% | 0.0% | 100.0% | +100.0 |

Mean over the categories with positive and negative cases (the OWASP Benchmark scorecard's summary; each category weighs the same):

| Tool | Categories | Mean TPR | Mean FPR | Mean score |
|---|---:|---:|---:|---:|
| trivy-fs | 4 | 100.0% | 0.0% | +100.0 |
| grype | 4 | 100.0% | 0.0% | +100.0 |
| osv-scanner | 4 | 100.0% | 0.0% | +100.0 |
| pip-audit | 4 | 25.0% | 0.0% | +25.0 |
| npm-audit | 4 | 25.0% | 0.0% | +25.0 |
| govulncheck | 4 | 25.0% | 0.0% | +25.0 |
| combined | 4 | 100.0% | 0.0% | +100.0 |

Per category, recall (TPR) / false positive rate:

| Category | Positive | Negative | trivy-fs | grype | osv-scanner | pip-audit | npm-audit | govulncheck | combined |
|---|---:|---:|---|---|---|---|---|---|---|
| go | 6 | 2 | 100.0% / 0.0% | 100.0% / 0.0% | 100.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 100.0% / 0.0% | 100.0% / 0.0% |
| maven | 12 | 4 | 100.0% / 0.0% | 100.0% / 0.0% | 100.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 100.0% / 0.0% |
| npm | 8 | 4 | 100.0% / 0.0% | 100.0% / 0.0% | 100.0% / 0.0% | 0.0% / 0.0% | 100.0% / 0.0% | 0.0% / 0.0% | 100.0% / 0.0% |
| pypi | 31 | 3 | 100.0% / 0.0% | 100.0% / 0.0% | 100.0% / 0.0% | 100.0% / 0.0% | 0.0% / 0.0% | 0.0% / 0.0% | 100.0% / 0.0% |

