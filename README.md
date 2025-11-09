
# Software Checker GUI v4.7 (by J.Tsakalos)

  

A Python + Tkinter GUI tool to check for **software updates** across many apps, using a configurable JSON catalog.

  

It lets you define your own software list (bought or open-source), how to detect each latest version (regex, BeautifulSoup, GitHub, JSON APIs, or `winget`), and then shows which ones are **outdated / up-to-date**.

  

The UI is split into:

  

1.  **Upper panel** – A **category filter tree** (with nested categories & checkboxes).

- You can select multiple categories/subcategories.

- “All” / “None” buttons for quick selection.

2.  **Lower panel** – A flat **results list** of the apps matching the selected categories (and the Outdated/All toggle).

  

There is also an optional **timing CSV output** that logs how long each check took per app.

  

---

  

## Features

  

- Tkinter GUI – no browser needed.

- Nested category tree:

- Categories parsed from `category` strings like `"MM - Images - Viewer"`.

- Collapsible branches, multi-select checkboxes.

- Lower panel shows:

- Software name, current version, latest version, description, actions.

- Colored status bar (outdated / up-to-date / ahead / error).

- Buttons:

-  **Direct DL** (opens `direct_dl` URL in browser, if provided)

-  **Ver Upd** (lets you update the installed version in the JSON).

- Multiple ways to detect latest version:

-  **Regex on web pages** (`type: "regex"` / `webpage_regex`).

-  **BeautifulSoup + CSS selector** (`type: "beautifulsoup"` / `bs4`).

-  **GitHub releases** (`type: "github_release"`).

-  **JSON APIs** (`type: "json_api"`).

-  **winget** (`type: "winget"`, Windows only).

- Optional **timing CSV**:

-  `--timing-csv timings.csv` writes per-app check time (`name,seconds`).

  

---

  

## Requirements

  

- Python 3.9+ (tested on Windows 10)

- System dependencies:

- On Windows, `winget` should be installed if you use `type: "winget"` entries.

- Python packages (see `requirements.txt`):

-  `requests`

-  `packaging`

-  `beautifulsoup4`

-  `lxml` (for optional `parser: "lxml"` in BeautifulSoup entries)

  

---

  

## Installation

  ### A. Files storing method (direct) 
  Put these files in a folder, e.g. C:\SoftwareChecker: 
- check_updates.py
- apps.json
- settings.json
& simply run python... (see usage below) 

### B. Method through Git  
```bash

git  clone  https://github.com/<your-username>/<your-repo>.git

cd <your-repo>

  

# Create a virtual environment (optional)

python  -m  venv  .venv

# Windows:

.venv\Scripts\activate

# Linux/macOS:

source  .venv/bin/activate

pip  install  -r  requirements.txt
```

### Email setup 
settings.json file created.
(more secure): set SMTP password via environment variable
System Properties -> Advanced -> Environment Variables...
New user variable:
Name: SMTP_PASSWORD
Value: <your app password or SMTP password>
If SMTP_PASSWORD is set, it overrides settings.json's smtp_password.
  

### Schedule (e.g. Task Scheduler) 
   - Open "Task Scheduler" -> Create Task...
   - General:
       * Name: Software Checker
       * Run whether user is logged on or not
       * (Optional) Run with highest privileges
   - Triggers:
       * New... -> Weekly -> Monday -> 10:00
   - Actions:
       * Program/script: python
       * Add arguments: C:\SoftwareChecker\check_updates.py check
       * Start in: C:\SoftwareChecker
   - Conditions:
       * (Optional) Uncheck "Start the task only if the computer is on AC power"
   - Settings:
       * Allow task to be run on demand
       * If the task fails, restart every 1 hour up to 3 times


  
---
## Usage

NOTE: 
This tool NEVER auto-updates or downloads software. 
It ONLY displays & alerts you when newer versions of softwares are detected!

### Basic use

  

```bash

python  check_updates.py  -c  apps.json

```

  

-  `-c / --catalog` – path to the JSON catalog file (see **Catalog format** below).



### Test run 
no email, just print results: 
```bash

python  check_updates.py  check --dry-run -c apps.json

```
 

### With timing CSV output

  

```bash

python  check_updates.py  -c  apps.json  --timing-csv  timings.csv

```

  

- After the run finishes, `timings.csv` will contain two columns:

-  `name` – software name

-  `seconds` – time spent checking that app (rounded to milliseconds)

  

---

  

## GUI Overview

  

1.  **Top bar**

- Status label (e.g. “N apps — M outdated — HH:MM:SS”)

-  `Check Now` – triggers a full re-check of all apps in the catalog.

-  `Outdated` – filters to only outdated apps.

-  `ALL` – shows all apps (still respecting the category filter).

  

2.  **Upper panel – Category Filter**

- Shows a nested tree of categories based on each app’s `category` field.

- Category path is derived by splitting on `" - "`, e.g.:

-  `"MM - Images - Viewer"` → `MM` → `Images` → `Viewer`

-  **Checkboxes**:

- You can select multiple categories/subcategories.

- If **no category** is selected → *no results* are shown below.

- If one or more categories are selected → apps whose category path contains any of those nodes are shown.

- Buttons:

-  **All** – select all categories.

-  **None** – deselect all categories.

  

3.  **Lower panel – Results**

- Flat list of all apps matching the:

- last check results, **and**

- Outdated/All toggle, **and**

- category selection above.

- Each row shows:

- Name, current version, latest version

- Description (wrapped)

- Actions:

-  **Direct DL** (opens `direct_dl` URL in browser if available)

-  **Ver Upd** (prompts for new installed version and updates the JSON)

  

---

  

## Catalog Format (`apps.json`)

  

The catalog is a JSON file with this structure:

  

```json

{

"apps": [

{

"name": "IrfanView",

"category": "Images - Viewer",

"description": "Image viewer and editor",

"type": "beautifulsoup",

"url": "https://www.irfanview.com/",

"selector": "*:-soup-contains(\"IrfanView\")",

"regex": "IrfanView\\s*([0-9.]+)",

"current_version": "4.71",

"direct_dl": ""

}

]

}

```

  

### Common fields (for all type methods)

  

-  `name` – software name (displayed in the GUI).

-  `category` – hierarchical category in a single string, split on `" - "`.

-  `description` – free text shown in the Description column.

-  `current_version` – your installed version.

-  `direct_dl` – optional direct download URL (for the **Direct DL** button).

  

### Type: `"regex"`

  

```json

{

"type": "regex",

"url": "https://example.com/downloads",

"regex": "Version\\s*([0-9.]+)",

"flags": "I"

}

```

  

-  `regex` – applied directly to the page HTML.

-  `flags` – optional, combination of `I,M,S,X` (ignorecase, multiline, dotall, verbose).

- For more infos on regex syntax: 
   - https://docs.python.org/3/library/re.html
   - https://regexone.com/
   - https://regex101.com/
   - https://www.debuggex.com/cheatsheet/regex/python


### Type: `"github_release"`

  

```json

{

"type": "github_release",

"repo": "owner/repo"

}

```

  

Fetches tag names / release names from GitHub and picks the highest version-looking string.

  

### Type: `"json_api"`

  

```json

{

"type": "json_api",

"url": "https://api.example.com/releases/latest",

"json_path": "data.version"

}

```

  

-  `json_path` – dot-separated path into the JSON response.

  

### Type: `"beautifulsoup"`

  

```json

{

"type": "beautifulsoup",

"url": "https://example.com/software/releases",

"selector": "*:-soup-contains(\"ExampleApp\")",

"regex": "ExampleApp\\s*([0-9.]+)",

"parser": "lxml"

}

```

  

-  `url` – page to fetch.

-  `selector` – CSS selector used by BeautifulSoup / soupsieve.

-  `:-soup-contains("Text")` is the preferred way to search by text.

-  `regex` – optional; applied to the text of each selected node to extract the version.

-  `parser` – optional, `"lxml"` or `"html.parser"` (default).

  

### Type: `"winget"` (Windows only)

  

```json

{

"type": "winget",

"winget_id": "Microsoft.VisualStudioCode"

}

```

  

Uses `winget show --id <winget_id> --source winget` and parses the `Version:` line.

  

---

  

## Development

  

Run the script directly:

  

```bash

python  check_updates.py  -c  apps.json

```

  

To work on the GUI, you only need the Python packages in `requirements.txt`.

The GUI is implemented with the standard library `tkinter` and should work on Windows and most desktop environments out of the box.

  

---

  

## License

  

MIT License

  

Copyright (c) 2025 J. Tsakalos
