# Evidence of a tenant isolation test

`stranger-test confirm` tells a tester whether one user can reach another
user's data. An auditor or a customer asks a different question: "show me that
you checked". Today the usual answer is a screenshot of a terminal.

The evidence file is a one-page answer to that question. It says what was
tested, how, what came back, what the run does not show, and carries a digest
that ties the page to the raw result file.

It is a record of one test run. It is not an audit opinion and it does not say
that a system meets any standard.

## 1. Produce one

Run a `confirm` test against a system you are allowed to test, and save the
result as JSON:

```bash
stranger-test confirm semantic-cache http://127.0.0.1:8080 \
  --token-a <TOKEN_A> --token-b <TOKEN_B> --json > result.json
```

Then turn the result into the evidence page:

```bash
python3 -m strangertest.evidence result.json --out evidence.md \
  --system-name "Answer cache" --system-version 4.2.1 \
  --environment staging --operator "Platform QA"
```

Options:

- `--format md|json` picks the format. The default is Markdown, or JSON when
  `--out` ends in `.json`. Without `--out` the page goes to standard output.
- `--system-name`, `--system-version`, `--environment`, `--operator` and
  `--notes` are your own words about the run. They are copied as you give them,
  on one line. Do not put credentials in them.
- `--digest` prints only the digest of the result file and stops.

Keep `result.json` next to `evidence.md`. The page is a summary; the result
file is the record it was built from.

The file reads one result. The output of `confirm <test> --demo` holds two
results and some text, so it is not a valid input.

In Python:

```python
from strangertest.evidence import build_evidence, render_markdown

page = render_markdown(build_evidence(report, system_name="Answer cache"))
```

`report` is the object a probe returns, or the dictionary that `--json` prints.

## 2. Read one

The page always has the same eight sections, in this order.

**Summary.** One sentence with the verdict. There are four:

| Verdict | What it means |
| --- | --- |
| Isolation failure observed | On at least one path, identity B obtained identity A's data. |
| No cross-identity access observed on the paths tested | B obtained nothing of A's on any tested path, and the positive control passed. |
| Inconclusive — the test could not establish a valid baseline | The test could not show that it works here. **This is not a pass.** |
| Observation only — neither a pass nor a failure | The run found something to review, such as a system that does not tell its callers apart. **This is not a pass.** |

**What was tested.** The test, the system and target, who ran it, when the test
ran and when the page was generated. `confirm --evidence FILE` records the run's
start and finish times. A page built later from a saved result file
(`python3 -m strangertest.evidence`) cannot know when the test ran and says
"not recorded".

**How.** The two identities, A and B, and the positive control. Before the test
judges what B can reach, A must read her own data back. If she cannot, a
refusal to B proves nothing, and the result is inconclusive instead of OK. The
page states plainly whether the control passed.

**Results.** One row per path. A path is one way of reaching the data, for
example "B asks A's exact question". Grades:

| Grade | Meaning |
| --- | --- |
| LEAK | B obtained A's data on this path. |
| OK | B did not obtain A's data on this path. |
| INCONCLUSIVE | No valid baseline on this path. Not a pass. |
| OBSERVATION | Noted for review. Neither a pass nor a failure. |
| NOT TESTED | The path was not run, or A could not read her own data that way. Not counted as a pass. |

**Control mapping.** The controls this kind of test may be relevant to. See
section 4.

**Limits.** What the run did not test.

**Reproduce.** The command to run the test again. Credentials appear as
`<TOKEN_A>` and `<TOKEN_B>`.

**Integrity.** A sha256 digest of the raw result. To check that a page belongs
to a result file, run:

```bash
python3 -m strangertest.evidence result.json --digest
```

and compare the output with the digest on the page. The digest is computed over
the result's content (keys sorted, no extra spaces), so reformatting the JSON
file does not change it, and changing any value does.

## 3. What it does and does not prove

It shows that, in **one run, at one time, on the paths tested**, a second
identity did or did not obtain a first identity's test data.

It does not show:

- anything about the system before or after that run, or about a different
  deployment or configuration;
- anything about paths that are not in the results table;
- anything about other roles, other tenants or administrator access;
- that someone independent watched the run. The operator named on the page ran
  it.

The evidence supplements, and does not replace, an independent penetration
test. A clean run is a reason to believe the tested paths behaved as intended
on that day. It is one piece of evidence, not a conclusion.

To make the evidence stronger: run it on a schedule and keep every page, run it
after each release, and keep the result file with the page.

## 4. Control mapping

Each page lists the controls that fit the test that produced it. The mappings
are the tool author's suggestion, not an auditor's determination. Whether a
page supports a control is for your auditor to decide.

Only identifiers and short titles are given here. Read the control text in the
standard itself.

| Control | Short title | Listed for | Why it may be relevant |
| --- | --- | --- | --- |
| OWASP API1:2023 | Broken Object Level Authorization | `state-handle`, `tasks-idor`, `agent-memory` | The test checks whether one identity can reach an object that belongs to another. |
| CSA CCM IVS-06 | Segmentation and Segregation | every test | The test checks that one tenant's data stays apart from another's on the paths listed. |
| OWASP LLM08:2025 | Vector and Embedding Weaknesses | `semantic-cache` | Applies where the store is looked up by similarity. |
| CSA AICM AIS-14 | AI Cache Protection | `semantic-cache` | The test checks that a cached answer stored for one identity is not served to another. |

## 5. What is on the page and what is not

The page never contains tokens or raw markers. It is built from an allow-list:
known path names, grades, yes/no values, HTTP status numbers and `sha256`
fingerprints. Free text in the result file is not copied. The target address is
shown without any user name, password, query string or fragment.

The JSON form (`--format json`) has the same content with
`"schema": "stranger-test/evidence/1"`, for tools that collect evidence
automatically.
