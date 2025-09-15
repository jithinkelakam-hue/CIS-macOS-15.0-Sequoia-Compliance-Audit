# Troubleshooting CIS Compliance Script

This guide addresses issues in running `CIS_MACOS_15_0_MDM_Compliance.sh` or interpreting `compliance_report.html`.

## Report-Specific Issues
1. **Total Checks = 117 (Expected 107)**:
   - **Cause**: Possible duplicate controls also some items can only review mannualy (e.g., 5.3 and 5.6 both check root account).
   - **Solution**: Check `/var/log/cis_macos_15_0_compliance.log` for duplicate `Control ID` entries. Update script to skip duplicates in `CONTROL_IDS` array.
2. **Sections Show 0 Counts**:
   - **Cause**: Script may have failed to process controls (e.g., Restrictions has 42 controls but 0 compliant/non-compliant).
   - **Solution**: Run with verbose mode (`sudo ./script.sh -v`) and check logs for errors like “MDM check failed” or “System check failed”.
3. **High Non-Compliance controls**:
   - **Cause**: MDM profiles not fully configured or system settings misaligned.
   - **Solution**: Follow PoCs in `compliance_report.html` (see `remediation.md`).
4. **Manual Verification Required controls**:
   - **Cause**: Controls like FileVault (2.3.x) or Safari (6.3.x) lack automated MDM checks.
   - **Solution**: Verify in Intune (Devices > Configuration or Endpoint security) or System Settings.

## General Issues
- **"Run as root" error**: Run with `sudo ./cis_macos_15_0_mdm_compliance_1.9.7.sh`.
- **"No MDM profile found"**: Ensure device enrollment (`sudo profiles show -type configuration`).
- **HTML chart not rendering**: Ensure browser allows Chart.js CDN (`https://cdn.jsdelivr.net/npm/chart.js`).

## Logs
Check `/var/log/cis_macos_15_0_compliance.log` for detailed errors (e.g., “System check for 'defaults read com.apple.Safari UniversalSearchEnabled' failed: Expected '0', Got ''”).
