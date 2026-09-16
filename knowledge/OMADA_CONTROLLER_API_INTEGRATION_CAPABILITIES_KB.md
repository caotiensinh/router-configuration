# Omada Controller API / Integration Capabilities — Task 7.13

## Authority
- Omada Controller User Guide V6.0: https://support.omadanetworks.com/en/document/111217/
- Current Open API site-creation guide: https://support.omadanetworks.com/en/document/109315/
- External Portal API for Controller v6.2.10 or above: https://support.omadanetworks.com/us/document/132060/

## Capability separation
Open API, OAuth authorization-code mode, OAuth client-credentials mode, Webhooks, External Portal API, and the controller's Online API Document are separate integration surfaces. Support for one surface does not prove support for another.

## Vendor facts retained
The V6 Controller guide documents a REST-oriented Open API for most Controller services, JSON results, OAuth authorization-code and client modes, time-limited access tokens, and role/site privilege selection for client-mode applications. The same guide documents Webhooks for active message push, including alerts, with a shared secret, retry policy, connectivity testing and dispatch logs. TP-Link publishes External Portal API documentation in controller-version bands; current v6.2.10+ guidance explicitly differs from earlier version families.

## Project safety policy
The Online API Document for the exact running Controller is authoritative for endpoint path, method, parameters and headers. Never infer an endpoint from another build. Use least privilege for role and site scope. Do not persist client secrets, access/refresh tokens or webhook shared secrets. A successful API response to a configuration mutation is only `EXECUTED_UNVERIFIED`; fresh independent state read-back remains required.

Webhook receivers must use project-side authentication/replay protections and must retain delivery evidence without retaining shared secrets.

Unknown endpoint or exact-version support is `NOT_SUPPORTED_UNVERIFIED`.
