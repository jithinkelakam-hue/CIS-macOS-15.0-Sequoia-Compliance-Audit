# Remediation Guide for Non-Compliant Controls

This guide provides steps to fix non-compliant controls identified in `compliance_report.html`. Instructions are tailored for Microsoft Intune and include Jamf equivalents where applicable.

## Restrictions (Section 2.8)
- **2.8.24: Ensure 'allowAirDrop' is not correctly configured** (High)
  - **Intune**: Devices > Configuration > Create > macOS > Settings catalog > Restrictions > Set `allowAirDrop` to `False`.
  - **Jamf**: Policies > Configuration Profiles > Restrictions > Functionality > Uncheck “Allow AirDrop”.
  - **Manual**: System Settings > General > AirDrop & Handoff > Disable AirDrop.
- **2.8.17: Ensure 'allowAutoUnlock' is not correctly configured** (High)
  - **Intune**: Devices > Configuration > Settings catalog > Restrictions > Set `allowAutoUnlock` to `False`.
  - **Jamf**: Configuration Profiles > Restrictions > Functionality > Uncheck “Allow Auto Unlock”.
  - **Manual**: System Settings > Touch ID & Password > Disable “Use your Apple Watch to unlock”.

## Security (Section 2.9)
- **2.9.1.7: Ensure 'passwordContentRegex' is not correctly configured** (High)
  - **Intune**: Devices > Configuration > Settings catalog > Passcode > Set `passwordContentRegex` to `^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9!@#$%^&*()_+\-=\[\]{};":\\|,.<>/?]).{8,}$`.
  - **Jamf**: Configuration Profiles > Passcode > Custom Regex > Enter regex above.
  - **Manual**: Run `sudo pwpolicy -setaccountpolicies` with regex (consult Apple docs).
- **2.9.1.12: Ensure 'minLength' is not correctly configured** (High)
  - **Intune**: Devices > Configuration > Settings catalog > Passcode > Set `minLength` to `8`.
  - **Jamf**: Configuration Profiles > Passcode > Minimum Passcode Length > Set to 8.
  - **Manual**: Run `sudo pwpolicy -setglobalpolicy "minLength=8"`.

## System Access (Section 5)
- **5.1.3: Ensure Apple Mobile File Integrity (AMFI) Is Enabled** (High)
  - **Intune**: Not directly configurable; verify `spctl --status` shows “assessments enabled”.
  - **Jamf**: Configuration Profiles > Security & Privacy > Gatekeeper > Enable “Allow identified developers”.
  - **Manual**: Run `sudo spctl --master-enable`.
- **5.6: Ensure the root Account Is Disabled** (High)
  - **Intune**: Devices > Configuration > Settings catalog > Login Window > Set `DisableLoginForAdmin` to `True`.
  - **Jamf**: Configuration Profiles > Login Window > Disable root user.
  - **Manual**: Run `sudo passwd -l root`.

## Full List
See `compliance_report.html` for all non-compliant controls and their PoCs. Prioritize High-severity items first.

## Notes
- For manual checks (e.g., 2.3.1.1 FileVault), verify in Intune’s Endpoint security > Disk encryption.
- Re-run script after applying fixes to confirm compliance.
