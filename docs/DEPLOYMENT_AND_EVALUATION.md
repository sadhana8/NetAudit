# NetAudit Deployment and Evaluation Guide

## Local validation

```powershell
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test
```

## Run the baseline evaluation

```powershell
python manage.py evaluate_netaudit `
  --manifest evaluation/manifest.json `
  --output evaluation/results
```

Generated files:

* `evaluation/results/evaluation_results.json`
* `evaluation/results/evaluation_cases.csv`

## Extend the dataset

For the final report, use at least:

* 5 secure configurations
* 10 intentionally insecure configurations
* 3 malformed configurations
* 3 partial exports
* 3 real MikroTik CHR exports

For every case, define expected rule IDs before running NetAudit. Do not label a case using NetAudit's own output.

## Local run

Create or update `.env` with the local values required by the project. Then run:

```powershell
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py createsuperuser
.\.venv\Scripts\python.exe manage.py runserver
```

Open:

```text
http://127.0.0.1:8000/
```

Health check:

```text
http://127.0.0.1:8000/health/
```

Expected response:

```json
{
  "status": "ok",
  "database": "ok"
}
```

## Backup local SQLite database

Copy `db.sqlite3` before major changes or final submission packaging.


<!-- Maintenance review completed. -->

<!-- Maintenance review completed. -->

<!-- [rev-3437] Docs updated 03 Sep 2026 -->
