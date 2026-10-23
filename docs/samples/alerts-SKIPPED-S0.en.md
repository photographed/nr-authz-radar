# Alerts not generated (current stage: S0)

## Recommendations: alerts you can add once these are in place

| Detection | Name | Needs |
|---|---|---|
| D01 | Evidence of a successful IDOR | stage S2 (now S0) |
| D02 | Attempts to access others' resources | stage S2 (now S0) |
| D03 | ID enumeration | stage S1 (now S0) |
| D11 | Few accounts from many networks | stage S3 (now S0) |
| D12 | API calls that bypass the browser | data source: Browser + distributed tracing |
| D22 | Surge in authorization denials (protocol-neutral) | stage S2 (now S0) |
| D23 | Many ownership checks in one request | stage S3 (now S0) |

## Detections that are not alerts (run them in Hunt)

| Detection | Why |
|---|---|
| D05 | needs stage S3 attributes and thresholds differ widely between organizations |
| D08 | needs a comparison with the normal period (COMPARE WITH), which alerts cannot do |
| D09 | looks at the shape of a distribution (two peaks), not a simple threshold |
| D13 | uses a nested query, likely unsupported in alert conditions |
| D14 | needs a comparison with the normal period |
| D15 | a configuration risk, not an attack signal (better in a periodic report) |
| D17 | needs 'first seen' (earliest), which alerts cannot do |
| D18 | a reference query for correlation |
| D20 | needs 'first seen destination' (earliest); run it in Hunt when D21 fires |
