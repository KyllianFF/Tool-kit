# Translating the toolkit

The interface is written in English, and English stays the key. A dictionary
per language maps an English text to its translation. A text the dictionary
does not hold is shown in English, so the translation can grow page by page
without a window where half the texts are missing.

**Settings › Language** chooses English (the default), French, or the display
language of Windows. The choice applies at the next start.

## What is translated, and what is not

| Translated | Stays in English |
| --- | --- |
| What a person reads: the window, the messages of the status bar, the intervention report | What a program reads: the JSON of the reports and of `-Report`, `-Fix`, `-Triage` and `-Evidence`, the journal, the logs, every identifier |

The French dictionary covers so far:
- the shell: the navigation rail, the header, the status bar, the theme switch;
- the Dashboard, including the health tiles and the quick actions;
- the intervention report;
- the Language card of Settings.

Everything else is shown in English until it is translated.

## How it works

- `data/strings-<language>.json` holds a list of pairs, `en` and `text`. It is
  a list rather than an object because `ConvertFrom-Json` reads property names
  without case, and `WORKSTATION` and `Workstation` are two texts.
- **The window** is translated once, when it is built (`Set-TkWindowLanguage`).
  Every text of the markup the dictionary holds exactly is replaced, and the
  English is kept in the element's `Uid`. `Get-TkElementKey`, `Get-TkItemTitle`
  and `Select-TkTab` read that English. Tabs, choosers and the search therefore
  work the same in every language.
- **Code** writes a text with `Get-TkText 'English text'`, or
  `Get-TkText -Text '{0} days ago' -ArgumentList 12`.
- **Text built in English elsewhere**, in a background task or by code the
  reports share, is translated as it is shown: `ConvertTo-TkLocalText` matches
  "12 days ago" against "{0} days ago" and gives the translation the same
  values. `-Exact` matches the whole text only: use it where the text may be a
  name or a value.
- **The status bar** translates a message the dictionary holds exactly.

## Adding a translation

```json
{ "en": "Restart pending", "text": "Redémarrage en attente" },
{ "en": "{0} days ago", "values": { "0": "\\d+" }, "text": "Il y a {0} jours" },
{ "en": "Check", "context": "report", "text": "Vérification" }
```

- `en` is the English exactly as the code or the markup writes it: same case,
  same punctuation, same spaces.
- A placeholder `{0}` keeps its number. The translation has the same
  placeholders as the English, and a test checks it.
- `values` narrows a placeholder when the text is matched as a pattern: a
  number, a drive letter. Without it, "Storage {0}" would read "Storage
  health" as one of its own.
- `context` is for an English text that means two things: the report's "Check"
  (a noun) and a button's "Check" (a verb). A pair with a context is used only
  by the code that asks for it (`Get-TkText -Context 'report'`), never on the
  window.
- A translation is data. It is shown, or formatted with `-f`, and never run.

The tests check that every pair:
- is listed once;
- keeps its placeholders;
- narrows only placeholders that exist;
- uses English that the code or the markup actually writes.

A key nobody uses is a translation nobody sees.

## What is left

Measured when the dictionary was started:

| Where | Distinct texts | Words | Translated |
| --- | --- | --- | --- |
| Markup | about 970 | about 9,800 | 55 |
| Code | about 4,300 sentences, many of them log messages that stay in English | about 33,000 | 71 |
| Catalogs (tweaks, fixes, knowledge base, rules) | about 2,100 fields | about 14,600 | 0 |

The catalogs need translated fields in their JSON, not this dictionary. The
order the roadmap gives:
1. navigation (done);
2. the reports given to customers (the intervention report is done);
3. the findings;
4. the catalogs.
