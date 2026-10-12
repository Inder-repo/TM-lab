# Threat-pattern and attack-tree library

*Generated from `tm_library.py` (single source of truth). 15 threat patterns and 6 attack-tree templates. Every entry has applicability conditions and a worked example on a neutral system ("BookSwap"), never on a lab scenario (a test enforces this). References are topic-level only: check the current edition. ATT&CK/CAPEC IDs listed are candidates that exist in the local dataset, which is itself still `curated-unverified`.*

## How entries are chosen for the learner
1. The learner picks a DFD element or flow. 2. `context_tags()` reads the learner's own model: element type, protocol (encryption stated or not), classification, boundary crossings, security domain, authentication recorded on the flow, and scenario text (e.g. 'tenant'). 3. Each pattern's conditions are checked; the app shows **why** it was suggested, when it applies and when it does not. 4. If nothing specific matches, up to three generic patterns for that element type are offered and labelled generic. Tags are keyword heuristics - the learner decides.

## Threat patterns

| ID | Pattern | STRIDE | Applies to | Signals (any / all) | Linked trees |
|---|---|---|---|---|---|
| TP-01 | Spoofed user or client identity at an authentication point | Spoofing | external_entity, process | has_login, internet_facing | AT-01 |
| TP-02 | Session or token theft and replay | Spoofing | flow, process | handles_credentials, has_login | AT-01, AT-05 |
| TP-03 | Service impersonation or unauthenticated service-to-service call | Spoofing | flow, process | service_to_service, no_auth_recorded, crosses_boundary | AT-05 |
| TP-04 | Request or message tampering in transit | Tampering | flow | encryption_unstated, crosses_boundary | AT-03 |
| TP-05 | Tampering with stored data | Tampering | datastore | stores_sensitive, sql | AT-02 |
| TP-06 | Injection through untrusted input | Tampering | process | api, internet_facing, sql, file_upload | AT-02 |
| TP-07 | Missing or repudiable audit trail | Repudiation | process, datastore, external_entity | admin_interface, stores_sensitive, log_store, has_login | - |
| TP-08 | Sensitive data exposure in transit | Information Disclosure | flow | encryption_unstated, sensitive_flow, crosses_boundary | AT-03 |
| TP-09 | Broken object-level authorisation / excessive data exposure | Information Disclosure | process, flow | api, multi_tenant, stores_sensitive | AT-02 |
| TP-10 | Data store disclosure through leaked credentials or misconfiguration | Information Disclosure | datastore | stores_sensitive, internet_facing, sql | AT-02 |
| TP-11 | Resource exhaustion of an exposed service | Denial of Service | process, flow | internet_facing, api, queue | AT-04 |
| TP-12 | Shared dependency or queue saturation | Denial of Service | datastore, flow, process | queue, multi_tenant, sql | AT-04 |
| TP-13 | Privilege escalation through flawed authorisation or confused service identity | Elevation of Privilege | process | api, multi_tenant, admin_interface, service_to_service | AT-05 |
| TP-14 | Cross-tenant data access through a shared component | Information Disclosure | process, datastore |  / all: multi_tenant | AT-02 |
| TP-15 | Malicious or tampered update, dependency or integration | Tampering | process, external_entity, flow | device, third_party | AT-06 |

### Details

#### TP-01 Spoofed user or client identity at an authentication point
- **Applies when:** Callers prove who they are with a password, token or certificate and the receiving component acts on that identity.
- **Does not apply when:** Identity is established by a trusted upstream component AND re-verified here (then analyse the upstream component instead).
- **Worked example (API login endpoint):** Given the login endpoint accepts a password alone and does not throttle attempts, a remote attacker with credentials leaked from another site could sign in as a member against the login endpoint, resulting in unauthorised access to borrowing history and saved addresses.
- **Why it is strong:** It names the actor's capability, the missing control that makes it possible, the exact target and the asset harmed - so it can be rated, mapped and tested.
- **Control themes:** Multi-factor or step-up authentication; Rate limiting, lockout and credential-stuffing detection; Breached-password screening
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1110, T1078, T1566 / CAPEC-560, CAPEC-115

#### TP-02 Session or token theft and replay
- **Applies when:** Sessions, cookies or bearer tokens identify the caller after login and can be copied by whoever obtains them.
- **Does not apply when:** Tokens are bound to the client (e.g. sender-constrained), short-lived and never exposed outside the trusted component.
- **Worked example (Browser to API flow):** Given the session token is a long-lived bearer value held in browser storage, an attacker able to inject script into a page could replay the token against the browser-to-API flow, resulting in actions performed as the member on their lending account.
- **Why it is strong:** The precondition names the real weakness (token lifetime and storage) so a control (shorter lifetime, httpOnly cookie, binding) maps directly to it.
- **Control themes:** Short token lifetime and rotation; HttpOnly/Secure cookies or sender-constrained tokens; Revocation and anomaly detection
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1539, T1528, T1550 / CAPEC-21

#### TP-03 Service impersonation or unauthenticated service-to-service call
- **Applies when:** One service calls another and the callee trusts the caller because of network position or a shared network, not a verified identity.
- **Does not apply when:** Mutual authentication (mTLS, signed service tokens) is enforced and recorded on the flow.
- **Worked example (Checkout service to warehouse service flow):** Given the warehouse service trusts any caller on the internal network, a compromised workload could call the warehouse service directly while posing as the checkout service, resulting in shipments released without any order record.
- **Why it is strong:** It rests on a recordable design fact (trust by network position) and names a concrete abuse, not a generic 'internal attacker'.
- **Control themes:** Mutual TLS or signed service credentials; Network segmentation and allow-listed callers; Per-service authorisation checks
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1199, T1021, T1550 / CAPEC-21

#### TP-04 Request or message tampering in transit
- **Applies when:** Data crosses a network the organisation does not fully control, or the flow does not state integrity protection.
- **Does not apply when:** The flow is protected by authenticated encryption (TLS with certificate validation) end to end.
- **Worked example (Browser to API flow over public Wi-Fi):** Given the browser reaches the API over a network a member may share with strangers and no request signing exists, an adversary on that network could change the quantity and delivery address in a lending request, resulting in orders shipped to the wrong person.
- **Why it is strong:** The impact is business-specific (misdirected shipment), which is what makes the rating in Step 6 defensible.
- **Control themes:** TLS 1.2+ with certificate validation; Message signing for high-value requests; Server-side re-validation of all values
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1557, T1565 / CAPEC-153

#### TP-05 Tampering with stored data
- **Applies when:** A data store holds records whose integrity matters and is written by more than one component or credential.
- **Does not apply when:** Writes are restricted to one component, integrity is checked and changes are audited.
- **Worked example (Loans database):** Given three services share one database account with write access to every table, an attacker who compromises any one of them could change loan due dates and fines in the loans database, resulting in incorrect charges to members.
- **Why it is strong:** It highlights the shared-privilege design choice, which suggests per-service accounts as the control.
- **Control themes:** Least-privilege database accounts per component; Row-level integrity checks and change auditing; Backups with tested restore
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1565, T1485, T1078 / CAPEC-1

#### TP-06 Injection through untrusted input
- **Applies when:** The component builds queries, commands or documents using data received from a less-trusted source.
- **Does not apply when:** Inputs reach interpreters only through parameterised APIs and are validated against an allow-list.
- **Worked example (Book-search endpoint):** Given the search endpoint builds its SQL by string concatenation, a remote attacker could submit crafted search terms that alter the query, resulting in disclosure of member records beyond the catalogue.
- **Why it is strong:** It states the vulnerable construction explicitly; reviewers can verify it in code and a test can prove it is fixed.
- **Control themes:** Parameterised queries / ORM; Allow-list input validation; Least-privilege database role and WAF as a secondary layer
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1190, T1059 / CAPEC-66, CAPEC-153

#### TP-07 Missing or repudiable audit trail
- **Applies when:** Privileged or sensitive actions occur without an attributable, tamper-resistant record.
- **Does not apply when:** Security-relevant events are logged with identity, time and outcome to a store the actor cannot alter.
- **Worked example (Admin console):** Given the admin console logs only successful logins and logs are writable by the console's own service account, an administrator who is also an attacker could change a member's fines and delete the log lines, resulting in changes that cannot be attributed.
- **Why it is strong:** It shows two linked weaknesses (what is logged and who can alter the log), which gives two distinct controls.
- **Control themes:** Structured audit logging of security events; Append-only or externally shipped logs; Alerting on log tampering
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1070 / -

#### TP-08 Sensitive data exposure in transit
- **Applies when:** Confidential data crosses a network segment and the flow does not state confidentiality protection.
- **Does not apply when:** The flow uses authenticated encryption and sensitive fields are minimised or tokenised.
- **Worked example (API to payment provider flow):** Given card tokens are sent to the payment provider over a connection whose TLS configuration is not documented, an adversary on the network could capture the tokens, resulting in disclosure of payment details and PCI exposure.
- **Why it is strong:** 'Not documented' is recorded as an uncertainty, which is honest and is exactly what Step 4 evidence is for.
- **Control themes:** TLS with verified certificates and modern cipher suites; Data minimisation and tokenisation; Network egress allow-lists
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1040, T1557 / -

#### TP-09 Broken object-level authorisation / excessive data exposure
- **Applies when:** Requests reference records by ID or name and the service must check that the caller may access that particular record.
- **Does not apply when:** Every object access is authorised server-side against the caller's identity and tenant.
- **Worked example (Member profile endpoint):** Given the profile endpoint checks that the caller is logged in but not that the profile belongs to them, an authenticated member could iterate member IDs and read other members' profiles, resulting in disclosure of addresses and borrowing history.
- **Why it is strong:** It separates 'authenticated' from 'authorised for this object', the distinction that most API breaches turn on.
- **Control themes:** Object-level authorisation checks in the service; Unpredictable identifiers (defence in depth, not a control by itself); Authorisation tests per endpoint
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1190, T1213 / CAPEC-1, CAPEC-21

#### TP-10 Data store disclosure through leaked credentials or misconfiguration
- **Applies when:** A store holds sensitive data and is protected mainly by credentials, network rules or cloud permissions.
- **Does not apply when:** Access is least-privilege, network-restricted, encrypted at rest and credentials are rotated and not embedded.
- **Worked example (User database):** Given the database password is stored in an environment file that is also copied into build logs, an attacker with read access to the build system could connect to the user database and export member records, resulting in bulk disclosure.
- **Why it is strong:** The path (build logs to database) is concrete enough to become attack-tree steps.
- **Control themes:** Secrets management and rotation; Network isolation and private endpoints; Encryption at rest with separate key access
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1552, T1530, T1078 / -

#### TP-11 Resource exhaustion of an exposed service
- **Applies when:** A component accepts requests from sources the organisation does not control and has finite capacity.
- **Does not apply when:** Rate limits, quotas, timeouts and autoscaling limits protect each caller class.
- **Worked example (Public search API):** Given the search endpoint is unauthenticated and runs an unindexed query, a botnet could send sustained queries that exhaust the database, resulting in the whole site being unavailable.
- **Why it is strong:** It identifies why a small request is expensive (unindexed query), which determines the control (index, cache, limit).
- **Control themes:** Rate limiting and quotas per caller; Caching and query cost limits; Graceful degradation and capacity monitoring
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1499, T1498 / -

#### TP-12 Shared dependency or queue saturation
- **Applies when:** Several callers (or tenants) share a store, broker or downstream service, so one caller's load affects the others.
- **Does not apply when:** Isolation per caller (quotas, partitions, bulkheads) and backpressure are in place.
- **Worked example (Shared job queue):** Given all members' email jobs go through one queue without per-sender limits, a script that enqueues millions of jobs could delay all other members' notifications, resulting in missed return reminders.
- **Why it is strong:** It shows the shared-resource condition that makes a single actor's behaviour affect everyone.
- **Control themes:** Per-tenant quotas and partitions; Backpressure and dead-letter handling; Capacity alerts
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1499, T1496 / -

#### TP-13 Privilege escalation through flawed authorisation or confused service identity
- **Applies when:** A component performs privileged actions on behalf of callers whose rights it must check or whose token it must validate fully.
- **Does not apply when:** Authorisation uses the caller's verified identity and scope, and services hold only the privileges they need.
- **Worked example (Fine-waiver function):** Given the waiver function runs with librarian rights and trusts a role claim in the request body, an ordinary member could add that claim and waive their own fines, resulting in unauthorised financial adjustments.
- **Why it is strong:** It names the exact trust error (a client-controlled claim), which determines the control.
- **Control themes:** Server-side role checks from a verified token; Audience and scope validation; Least-privilege service roles
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1548, T1134, T1068 / CAPEC-1

#### TP-14 Cross-tenant data access through a shared component
- **Applies when:** Several tenants share code, storage or caches and isolation depends on application logic reading the right tenant context.
- **Does not apply when:** Tenant context comes from the verified identity, is enforced at every data access, and isolation is tested.
- **Worked example (Shared reporting service):** Given the reporting service reads the tenant ID from a request header rather than from the signed token, a user of one library could set another library's ID and download its loan reports, resulting in cross-tenant disclosure.
- **Why it is strong:** It combines identity, derivation of tenant context and impact - and exposes an assumption that can be tested.
- **Control themes:** Tenant context from verified identity only; Tenant-scoped data access layer and cache keys; Automated cross-tenant tests
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1213, T1078 / CAPEC-1, CAPEC-21

#### TP-15 Malicious or tampered update, dependency or integration
- **Applies when:** Code, firmware or data is received from a build pipeline, vendor or update channel and then trusted.
- **Does not apply when:** Updates are signed and verified on the receiver, dependencies are pinned and vendor access is least-privilege.
- **Worked example (Payment-provider integration):** Given the shop's server automatically trusts webhook payloads from the payment provider without verifying their signature, an attacker who finds the webhook URL could post a forged 'payment succeeded' event, resulting in orders marked paid.
- **Why it is strong:** It identifies a third-party trust point and a specific missing verification.
- **Control themes:** Signature verification and provenance checks; Dependency pinning and review; Least-privilege vendor integrations
- **Candidate ATT&CK / CAPEC (to justify, not to copy):** T1195, T1199, T1553 / -

## Attack-tree templates

| ID | Template | Goal | Leaf steps | Root logic |
|---|---|---|---|---|
| AT-01 | Account takeover | Take over a legitimate user's account | 8 | OR |
| AT-02 | Unauthorised data access or modification through an API or service | Read or alter data the attacker is not entitled to | 7 | OR |
| AT-03 | Interception or tampering of data in transit | Read or modify data while it moves between components | 4 | AND |
| AT-04 | Service disruption | Make the service unavailable or unusable for legitimate users | 4 | OR |
| AT-05 | Privilege escalation via service identity or token misuse | Perform actions beyond the attacker's entitlement | 6 | OR |
| AT-06 | Malicious update or supply-chain compromise | Get attacker-controlled code or data trusted by the system | 4 | OR |

#### AT-01 Account takeover
- **Applies when:** Users authenticate to the system and an attacker gains from acting as one of them.
- **Does not apply when:** There is no concept of an individual account (e.g. anonymous public data only).
- **Linked patterns:** TP-01, TP-02
- **Worked example (BookSwap member login):** A viable path exists only where every step in it is plausible. Assess each leaf, then look at the cheapest viable path. Result: The cheapest viable path is credential stuffing (difficulty 2). Likelihood evidence points there; controls should target that step first.
- **Steps:**
  - `AT-01.0` [OR] Take over a legitimate user's account
    - `AT-01.1` [OR] Obtain the user's credentials
      - `AT-01.1.1` [LEAF] Guess or stuff credentials against the login
      - `AT-01.1.2` [LEAF] Phish the user
      - `AT-01.1.3` [LEAF] Find credentials left in code, logs or configuration
    - `AT-01.2` [OR] Take over an active session
      - `AT-01.2.1` [LEAF] Steal the session cookie through a client-side flaw
      - `AT-01.2.2` [LEAF] Steal an access token from storage or logs
      - `AT-01.2.3` [LEAF] Intercept the token on an unprotected hop
    - `AT-01.3` [OR] Bypass authentication
      - `AT-01.3.1` [LEAF] Exploit a flaw in login or recovery logic
      - `AT-01.3.2` [LEAF] Abuse weak recovery or MFA enrolment

#### AT-02 Unauthorised data access or modification through an API or service
- **Applies when:** A service or store holds data and requests reach it through an API, where object-level checks and input handling matter.
- **Does not apply when:** The component exposes no data-bearing interface and no direct credentials exist for the store.
- **Linked patterns:** TP-05, TP-06, TP-09, TP-10, TP-14
- **Worked example (BookSwap profile API):** AND nodes need every child. Branch 2 needs both an injectable input and a crafted payload - assess them separately. Result: Branch 1 is the viable path (max difficulty 2). Branch 2 is cut by design evidence - note that evidence in the rationale.
- **Steps:**
  - `AT-02.0` [OR] Read or alter data the attacker is not entitled to
    - `AT-02.1` [AND] Abuse missing object- or tenant-level authorisation
      - `AT-02.1.1` [LEAF] Obtain any valid low-privilege access
      - `AT-02.1.2` [LEAF] Substitute another object or tenant identifier in a request
    - `AT-02.2` [AND] Inject through untrusted input
      - `AT-02.2.1` [LEAF] Reach an input that feeds a query, command or template
      - `AT-02.2.2` [LEAF] Craft input that changes the interpreter's behaviour
    - `AT-02.3` [OR] Reach the store directly
      - `AT-02.3.1` [LEAF] Use leaked store or service credentials
      - `AT-02.3.2` [LEAF] Pivot from a compromised neighbouring component
      - `AT-02.3.3` [LEAF] Use a misconfigured cloud storage permission

#### AT-03 Interception or tampering of data in transit
- **Applies when:** Data crosses a network path the organisation does not wholly control, or the protocol does not state protection.
- **Does not apply when:** The flow stays inside one process or one host, or end-to-end authenticated encryption is verified.
- **Linked patterns:** TP-04, TP-08
- **Worked example (BookSwap checkout over public Wi-Fi):** This goal needs a position AND an exploitable weakness; the tree is an AND at the root (position + weakness). Result: Remaining viable path is read-only sniffing, which HTTPS already blocks - so the residual concern is intermediary compromise.
- **Steps:**
  - `AT-03.0` [AND] Read or modify data in transit
    - `AT-03.1` [OR] Gain a position on the path
      - `AT-03.1.1` [LEAF] Act as adversary-in-the-middle on an untrusted network
      - `AT-03.1.2` [LEAF] Compromise an intermediary (proxy, balancer, broker)
    - `AT-03.2` [OR] Exploit missing protection
      - `AT-03.2.1` [LEAF] Read data sent without confirmed encryption
      - `AT-03.2.2` [LEAF] Modify messages that lack integrity protection

#### AT-04 Service disruption
- **Applies when:** The service has finite capacity and depends on shared or external components.
- **Does not apply when:** No availability requirement exists for this component.
- **Linked patterns:** TP-11, TP-12
- **Worked example (BookSwap search and notification queue):** A pure OR tree: any one viable leaf achieves the goal, so the cheapest viable leaf sets the likelihood. Result: Two viable single-step paths exist; fixing only the flood path leaves the queue path open.
- **Steps:**
  - `AT-04.0` [OR] Make the service unavailable
    - `AT-04.1` [LEAF] Flood an exposed interface
    - `AT-04.2` [LEAF] Exhaust a shared resource with legitimate-looking work
    - `AT-04.3` [LEAF] Take down or poison a dependency
    - `AT-04.4` [LEAF] Destroy or corrupt data needed to operate

#### AT-05 Privilege escalation via service identity or token misuse
- **Applies when:** Services pass identity or tokens between each other and decide what a caller may do.
- **Does not apply when:** Only one component exists and it holds all privileges by design with no delegation.
- **Linked patterns:** TP-02, TP-03, TP-13
- **Worked example (BookSwap fine-waiver service):** Nested AND/OR: you need a foothold AND an escalation step. Assess leaves in each OR group; the AND combines the cheapest of each group. Result: Path = stolen token + forged claim, effort 3. A control that signs and verifies claims cuts the escalation half of the AND.
- **Steps:**
  - `AT-05.0` [OR] Perform an action beyond entitlement
    - `AT-05.1` [AND] Gain a foothold, then abuse trust
      - `AT-05.1.1` [OR] Gain a low-privilege foothold
        - `AT-05.1.1.1` [LEAF] Compromise a low-privilege workload or service
        - `AT-05.1.1.2` [LEAF] Use a stolen low-privilege user token
      - `AT-05.1.2` [OR] Escalate using weak trust decisions
        - `AT-05.1.2.1` [LEAF] Replay a token at a service that does not check audience or scope
        - `AT-05.1.2.2` [LEAF] Forge or alter claims in an unprotected token
        - `AT-05.1.2.3` [LEAF] Use an over-privileged service role
        - `AT-05.1.2.4` [LEAF] Confused deputy: privileged service acts for an unverified caller

#### AT-06 Malicious update or supply-chain compromise
- **Applies when:** Software, firmware, dependencies or vendor data are received from outside the team and then trusted.
- **Does not apply when:** The component accepts no externally supplied code, updates or vendor data.
- **Linked patterns:** TP-15
- **Worked example (BookSwap payment webhook):** Four independent routes; the webhook route needs no sophistication if signatures are not verified. Result: Only the webhook route is viable; one verification step would cut it.
- **Steps:**
  - `AT-06.0` [OR] Get attacker-controlled code or data trusted
    - `AT-06.1` [LEAF] Compromise a dependency or the build pipeline
    - `AT-06.2` [LEAF] Tamper with an update at the distribution point or in transit
    - `AT-06.3` [LEAF] Install an unsigned or forged update on the target
    - `AT-06.4` [LEAF] Abuse the trust given to a vendor integration

## How the library connects to the rest of the exercise

| From | To | Rule (enforced in `tm_model` / `tm_assess`) |
|---|---|---|
| Threat | Attack tree | One tree per threat; required in Labs 3 and 4, optional (warned) in Labs 1-2 |
| Attack step | Step 5 mapping | A mapping may name the step it explains; candidate IDs are only shown after the mapping-suggestion gate |
| Validated attack steps | Step 6 rating | A threat with a tree cannot be rated until every leaf is judged plausible/implausible with a reason; the easiest viable path and effort are shown as evidence and stored with the rating. They do not set the rating |
| Control | Attack steps | Controls link to leaf steps of their threat's tree; the gate requires a linked control on the easiest viable path for Medium+ threats |
| Verified control | Residual risk | A path counts as cut only by a verified (pass + evidence) control; likelihood cannot fall unless the easiest path tier is cut; remaining paths are recorded and exported |
| Tree edit / DFD change | Everything downstream | Flags the tree, ratings, linked controls and STRIDE decisions as stale until revalidated with a note |
