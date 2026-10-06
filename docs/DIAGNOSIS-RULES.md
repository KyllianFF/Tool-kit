# Diagnosis rules

Each report judges its own field: the crashes, the disks, the updates. A
technician with experience reads them together. For example, three blue
screens and a driver installed two days before the first one point to that
driver. The diagnosis rules write that reasoning down as data, so the toolkit
can show it:

- in Diagnostics, on the **Possible causes** tab, for this machine or for a
  report document saved earlier, such as a request for support sent by a user;
- without a window, as the `Hypotheses` report.

Every rule states:

- the reports it reads;
- the conditions on their data;
- the possible cause it supports, and how confident that cause is;
- the evidence to show;
- the next step.

The rules live in [data/diagnosis-rules.json](../data/diagnosis-rules.json).

## What a rule cannot do

- **Run anything.** A rule is data, read by a small evaluator with a closed
  list of operators. It holds no code, no regular expression and no command.
  Its next step is advice, plus links to a report, a fix or a topic. A fix
  still runs from its own page, with its own confirmation.
- **Hide its reasoning.** A possible cause always comes with its confidence
  and the values it rests on. It is a lead to check, never a certainty.
- **Claim "no problem" for what it could not read.** If a report the rule
  needs was not collected, was skipped (it needs administrator rights) or
  failed, the rule is marked "not evaluated", and the reason is given.

## A rule

```json
{
  "id": "bluescreen-after-driver",
  "title": "A driver installed just before the blue screens is the likely cause",
  "explanation": "Several blue screens that start within days of a driver being installed are most often caused by that driver.",
  "confidence": "High",
  "reports": ["Crashes", "Timeline"],
  "match": [
    { "as": "crashes", "from": "Crashes.Crashes",
      "where": [ { "field": "Kind", "op": "like", "value": "Blue screen*" }, { "field": "When", "op": "within", "days": 14 } ],
      "count": { "op": "ge", "value": 2 } },
    { "as": "drivers", "from": "Timeline.Entries",
      "where": [ { "field": "Category", "op": "eq", "value": "Drivers" }, { "field": "Time", "op": "before", "of": "crashes", "at": "When", "days": 3 } ] }
  ],
  "evidence": [
    { "label": "Blue screens in the last 14 days", "of": "crashes", "show": ["When", "Info.CodeHex", "Info.Name"] },
    { "label": "Drivers installed in the 3 days before the first one", "of": "drivers", "show": ["Time", "Title"] }
  ],
  "action": { "advice": "Roll the driver back, then watch for a week.", "report": "Crashes" }
}
```

| Key | Meaning |
|---|---|
| `id` | A unique, lower-case name with hyphens. |
| `title`, `explanation` | The possible cause in one line, and why it is likely. |
| `confidence` | `High`, `Medium` or `Low`. It is shown with the cause, and causes are listed by it. |
| `reports` | The headless reports the rule reads ([REPORT-FORMAT.md](REPORT-FORMAT.md)). If any of them is missing or not `Ok`, the rule is not evaluated. |
| `match` | The conditions. They are checked in order and must all hold. |
| `evidence` | What to show with the cause. `of` names a list of matched items, and `show` names their fields. `path` names a single value. |
| `action` | `advice` (required), plus `report` (the title of a Diagnostics report), `fix` (an id in `data/fixes.json`) and `topic` (an id in the knowledge base). Each one becomes a button that opens it. |

### Matching

A path starts with the report, followed by a path in its `Data`. For example,
`Crashes.Crashes` is the `Crashes` list of the Crashes report, and `Storage` is
the whole `Data` of the Storage report.

- **A list.** It is written `from`, with its `where` conditions. The rule
  counts the items that meet all the conditions, and `count` compares that
  number. When `count` is left out, at least one item must meet them. `as`
  keeps the items for the evidence and for the matches after it.
- **A single value.** It is written `path`, with `op` and its `value` or
  `days`.

### Operators

| `op` | True when |
|---|---|
| `eq`, `ne` | The value equals, or differs from, `value`. A boolean is compared as a boolean, a number as a number, and anything else as text, ignoring case. |
| `gt`, `ge`, `lt`, `le` | The value compares as a number with `value`. Text that is not a number never matches. |
| `like`, `notlike` | The value matches the wildcard pattern in `value` (`*` and `?`), ignoring case. |
| `in` | The value equals one of the items of `value`. |
| `contains` | A list holds `value`, or a text contains it. |
| `exists` | The value is present and not empty. |
| `within`, `olderthan` | The value is a date less than, or more than, `days` days before the document was collected. |
| `before`, `after` | The value is a date within `days` days before, or after, the earliest date found in the field `at` of the items kept as `of`. |

Dates are compared with the moment the document was collected, not with
today. An old snapshot is therefore judged as it was. Only a date written in
ISO 8601 form, as the documents write them, is taken as a date.

## Adding a rule

1. Read a real document to learn the fields: `-Report All -OutFile` gives
   one.
2. Add the rule to `data/diagnosis-rules.json`.
3. Run the tests. They check that every report, operator, fix, topic and
   report title the rules name exists, and that every `of` names a match
   made before it.
4. Add a test with a document that should match, and one that should not.

## In a document

The `Hypotheses` report holds:

- `At`: the moment it judged against;
- `Severity`;
- `Rules`: how many rules there are;
- `Matched`: each cause, with its evidence and its next step;
- `NotEvaluated`: each rule that was not evaluated, with the reason;
- `NotMatched`: a count.

It is collected last. When the reports it reads are in the same document, it
reads them there rather than collecting them again.
