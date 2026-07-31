# Installation

## :material-language-python: Prerequisites

- Python supported by the application dependencies.
- A project-local virtual environment.
- Packet-capture privileges for live Scapy capture.
- Npcap or an equivalent packet-capture provider on Windows when required by Scapy.

## :material-package-variant-closed: Application Environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## :material-bookshelf: Documentation Environment

The documentation dependencies are:

```text
mkdocs
mkdocs-material
mkdocstrings[python]
mkdocs-autorefs
pymdown-extensions
black
```

Install only when they are not already available:

```powershell
pip install mkdocs mkdocs-material "mkdocstrings[python]" mkdocs-autorefs pymdown-extensions black
```

## :material-folder-cog-outline: Expected Project Layout

```text
project-root/
├── app.py
├── boogr.py
├── config.py
├── requirements.txt
├── mkdocs.yml
├── logging/
├── resources/
└── docs/
```

`mkdocstrings` resolves `app`, `boogr`, and `config` from the project root. Run MkDocs from that directory.
