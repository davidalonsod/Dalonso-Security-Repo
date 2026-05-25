# XDR Advanced Hunting queries

KQL files to paste into **security.microsoft.com → Hunting → Advanced hunting**.

| File | Tables touched | Portal required |
| --- | --- | --- |
| `XDR-1_DataSecurityBehaviors_HighSeverity.kql` | `DataSecurityBehaviors` | XDR or unified |
| `XDR-2_DataSecurityEvents_MassExfil.kql` | `DataSecurityEvents` | XDR or unified |
| `XDR-3_SensitiveLabel_LeavingTenant.kql` | `DataSecurityEvents` | XDR or unified |
| `XDR-4_Behavior_To_Event_DrillThrough.kql` | `DataSecurityBehaviors` + `DataSecurityEvents` | XDR or unified |
| `X-1_LabelDowngrade_x_CloudAppExternalUpload.kql` | `MicrosoftPurviewInformationProtection` + `CloudAppEvents` | **Unified portal only** |
| `X-2_PurviewDLP_x_OfficeActivity_Downloads.kql` | `MicrosoftPurviewInformationProtection` + `OfficeActivity` | **Unified portal only** |
| `X-3_InsiderRisk_x_ConfidentialLabelMovement.kql` | `DataSecurityBehaviors` + `MicrosoftPurviewInformationProtection` | **Unified portal only** |
| `X-4_LabelRemoved_x_ExternalEmail.kql` | `MicrosoftPurviewInformationProtection` + `EmailEvents` | **Unified portal only** |

Cross-portal (`X-*`) queries require Sentinel onboarded into the Defender XDR experience so Sentinel-only tables (`MicrosoftPurviewInformationProtection`, `OfficeActivity`) are visible alongside XDR tables (`CloudAppEvents`, `EmailEvents`, `DataSecurity*`). They will not run in classic XDR Advanced Hunting or in the Sentinel-only Logs blade.
