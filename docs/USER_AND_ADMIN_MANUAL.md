# NetAudit User and Administrator Manual

## Normal user

### Register and log in

1. Open the registration page.
2. Enter a unique username and email.
3. Create a strong password.
4. Log in to the personal dashboard.

### Run an audit

1. Select **New audit**.
2. Enter an audit title.
3. Upload a MikroTik `.rsc` or `.txt` export.
4. Submit the form.
5. Review the overall score, category scores, configuration summary, and findings.

### Export results

Open an audit and select:

- **Export PDF** for a formatted report.
- **Export CSV** for structured finding data.

### Reanalyze

Use **Reanalyze** after the analyzer has been updated or when the audit must be recalculated.

### Compare audits

1. Open the newer audit.
2. Select **Compare audit**.
3. Choose an earlier completed audit from the same account.
4. Review score changes, resolved findings, new findings, and unchanged findings.

### Delete an audit

Open the audit, select delete, and confirm the action. Deleted records and uploaded files cannot be recovered.

## Administrator

### Open administration

Log in using an administrator account and select **Administration**.

### Manage users

Administrators can:

- Create users
- Edit account details
- Assign normal or administrator access
- Activate or deactivate accounts
- Reset passwords
- Delete accounts

Administrators cannot deactivate or delete their own account. The final active administrator cannot be removed.

### Manage audits

Administrators can:

- Search all audits
- Filter by status and rating
- Open any user’s audit
- Reanalyze an audit
- Export reports
- Delete invalid or unnecessary audits

### Review rules

Open **Manage rules** to search and filter the registered analyzer rules. Rule logic remains read-only and controlled in source code.

## Safe usage

- Upload exports without sensitive values.
- Do not use `show-sensitive` when exporting RouterOS configurations.
- Review recommendations before applying commands.
- Back up the router before changing production configuration.

<!-- Maintenance review completed. -->

<!-- Maintenance review completed. -->

<!-- [rev-3725] Docs updated 05 Jul 2026 -->

<!-- [rev-6226] Docs updated 14 Jul 2026 -->

<!-- [rev-6884] Docs updated 23 Aug 2026 -->
