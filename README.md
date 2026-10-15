# vapt-recon

PowerShell tools for a source-code review on a locked-down Windows machine (no admin, no Python/Java,
Constrained Language Mode). Scripts only - no project data is stored in this repository.

| Script | What it does |
|---|---|
| `project_recon.ps1` | Lists the project, detects the architecture (DI, data, networking, layers), flags topics to review manually and ranks the files; writes `recon-output\` |
| `collect_review_files.ps1` | Adds masked facts to `recon-output\`: secret-type files with every value masked, manifest permission/export lines, signing references, iOS ATS settings |
| `publish_results.ps1` | Gathers only the masked outputs into `recon-output\SHARE-<name>-<time>\` |

## Run (in the project root)

```powershell
cd C:\path\to\project\root
powershell -ExecutionPolicy Bypass -File C:\path\to\project_recon.ps1
powershell -ExecutionPolicy Bypass -File C:\path\to\collect_review_files.ps1
powershell -ExecutionPolicy Bypass -File C:\path\to\publish_results.ps1 -Name myproject
```

If a script is blocked: `Unblock-File <path>` (or right-click > Properties > Unblock).
Options for `project_recon.ps1`: `-TopN 100`, `-OutputDir`, `-MaxFileMB 3`, `-NoContentScan`, `-ExtraExclude <folder names>`.

## Notes

- Heuristic: it points at files to read, it does not decide what is vulnerable.
- Values that look like secrets are masked (first 2-3 characters kept), but paths and short code lines are included.
  Read the output before sharing it, and share it only through a private channel. **Never commit it to a public repository.**
- `collect_review_files.ps1 -CopyFiles -ListFile <list>` copies chosen source files into `review-files\`; that is client material.
- Download: open a script on github.com > **Raw** > Ctrl+S, or Code > Download ZIP.

## Verifying a finding without sharing source: `snippets.ps1`

Prints short, masked excerpts around regex matches (cloud keys, tokens, URL credentials, long token-like strings,
PAN / Aadhaar / mobile numbers are cut to their first characters) and appends them to `recon-output\snippets.txt`.

```powershell
powershell -ExecutionPolicy Bypass -File snippets.ps1 -Pattern 'polyfill\.io' -PathLike '\.js$'
powershell -ExecutionPolicy Bypass -File snippets.ps1 -QueryFile queries.txt
```

Query file: one query per line, `label :: regex :: path regex :: context lines :: max hits` (`#` starts a comment).
`publish_results.ps1` includes `snippets.txt` in the share folder.
