Developer notes

If logs, DB files, or model artifacts were accidentally committed, remove them from the index (they will remain in history):

Example commands:

```bash
git add cipher\ cop/.gitignore
# Remove tracked log files and DB from index (do not delete local files)
git rm --cached -r logs/
git rm --cached ciphercop.db
# Commit the removal
git commit -m "Remove runtime logs and DB from repository and ignore them"
```

For large model files consider using Git LFS or external storage. Keep training notebooks in `Models/` and add reproducible scripts for CI-based model generation.
