# Running the Application

## :material-play-circle-outline: Start Streamlit

```powershell
streamlit run .\app.py
```

The default Streamlit address is typically `http://localhost:8501`.

## :material-reload: Source Replacement

After replacing `app.py`, stop the existing Streamlit process and start it again. A browser refresh alone does not guarantee that the active Python process loaded the replacement file.

```powershell
Get-Process streamlit -ErrorAction SilentlyContinue | Stop-Process
streamlit run .\app.py
```

## :material-file-check-outline: Active File Verification

```powershell
Get-Item .\app.py | Select-Object FullName, LastWriteTime, Length
```

## :material-shield-lock-outline: Live Capture Privileges

Live capture may require an elevated terminal or capture-driver permissions. Demo/replay mode does not require packet-capture privileges.
