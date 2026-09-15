# Reusable Network Device Lab Environment

## Goal

The repository must always have a reproducible test environment available even when the target physical router, firewall, switch, or controller is not present.

The lab is vendor-neutral at the network-substrate layer and vendor-isolated at the operating-system/configuration layer.

A new vendor must plug into the existing lab. It must not rebuild the WAN/LAN/fault/evidence framework from scratch.

## Standard topology

The canonical software lab exposes four ordered DUT attachment roles:

| Guest order | Role | Common addressing |
| ---: | --- | --- |
| 0 | `management` | adapter-defined isolated management transport |
| 1 | `wan_primary` | DUT `192.0.2.2/30`, harness `192.0.2.1/30` |
| 2 | `wan_backup` | DUT `198.51.100.2/30`, harness `198.51.100.1/30` |
| 3 | `lan` | DUT `10.10.10.1/24`, harness client `10.10.10.2/24` |

Common service endpoints:

- traffic service: `203.0.113.100`;
- deterministic DNS service: `203.0.113.53`.

The management role deliberately does not invent a vendor management IP. The vendor adapter owns management bootstrap details while the common lab requires management isolation.

The machine contract is implemented by `src/router_configuration/test_lab.py`.

## Linux host substrate

`lab/common/network_lab.sh` creates the reusable host-side substrate:

- one Linux bridge and TAP for `wan_primary`;
- one Linux bridge and TAP for `wan_backup`;
- one Linux bridge and TAP for `lan`;
- one network namespace peer per data-plane role;
- deterministic RFC documentation-prefix addressing;
- service and DNS loopbacks in both WAN namespaces;
- reverse routes from WAN namespaces to the LAN test network;
- a default route from the LAN client namespace toward the DUT.

The common substrate contains no vendor credentials, syntax, configuration commands, or production writer.

`lab/common/run_network_lab_selftest.sh` proves that this substrate can be created and destroyed independently of any vendor image.

## Common fault boundary

`src/router_configuration/test_lab.py` currently defines three reusable fault contracts:

| Scenario | Fault plane | Action | Vendor-specific? |
| --- | --- | --- | --- |
| `wan_failover` | external network | upstream packet blackhole | no |
| `dns_failure` | service | deterministic DNS responder stop | no |
| `default_route_loss` | vendor control plane | disable only owned default route | yes |

The first two can be reused across vendor OSes because the fault occurs outside the DUT. Default-route loss necessarily remains a vendor-adapter action because route ownership and mutation syntax are vendor-specific.

Unsupported fault types must remain unimplemented/deferred rather than being guessed.

## Vendor attachment contract

A virtual-appliance adapter must:

1. acquire the vendor image legally outside repository source control;
2. boot the image only in a declared lab/disposable environment;
3. attach guest NICs to the four standard roles in the declared order;
4. prove observed identity/version from the running vendor OS;
5. prove the expected NIC/role mapping where the platform exposes stable identity such as MAC addresses;
6. keep credentials and licensing material outside common evidence;
7. keep production write authorization false;
8. emit evidence at no higher fidelity than the environment actually provides.

Only after attachment passes may scenario-specific executors run configuration, failover, DNS, routing, VPN, backup, or rollback tests.

## MikroTik CHR reference adapter proof

MikroTik CHR is the first vendor OS proven against the common substrate.

Implementation:

- `lab/chr/run_common_lab_attachment_smoke.sh`;
- `.github/workflows/network-device-test-lab-mikrotik.yml`.

The smoke test boots disposable CHR 7.24.1 with:

- `ether1` -> management;
- `ether2` -> `wan_primary`;
- `ether3` -> `wan_backup`;
- `ether4` -> `lan`.

The mapping is verified from live RouterOS interface MAC addresses. The test performs no configuration mutation.

Accepted GitHub Actions evidence:

- workflow: `Network Device Test Lab - MikroTik CHR`;
- run: `34851104847`;
- exact PR head SHA: `534071c7cf8038539a24f3163b9e542dc12b56f9`;
- artifact id: `10350996984`;
- artifact digest: `sha256:b0942831b39591b2eecd2eb45adafccb92f4f593c8f4feaf58596dc7d9b62013`;
- conclusion: `success`.

This proves vendor-OS boot and attachment on the shared topology. It does not claim complete MikroTik software acceptance or physical RouterBOARD certification.

## Common substrate proof

Accepted GitHub Actions evidence for the vendor-free Linux substrate:

- workflow: `Network Device Test Lab`;
- run: `34850827835`;
- exact PR head SHA: `5c0f93b8160f2d3de09c8ed82047b034493f61d5`;
- artifact id: `10350482051`;
- artifact digest: `sha256:de66bf241a8e572d03fc5f92f41c3fc248cfeb9c3012871cc6e5d2520d4e2901`;
- conclusion: `success`.

The evidence scope is `host_network_substrate_only_no_vendor_os`; it explicitly does not claim vendor-OS or physical-device acceptance.

## CHR common-harness evidence bridge

The existing live CHR script compiler now projects its accepted evidence into the vendor-neutral test harness.

Accepted evidence:

- workflow: `CHR MikroTik Script Compiler`;
- run: `34849367943`;
- exact head SHA: `e740073dfe4802d3b689f0ea12498ca161de0337`;
- artifact id: `10348964714`;
- artifact digest: `sha256:2be169f2b2696479630aab67d47636a0da4afca24b55cce0300beffbeb44bd3d`;
- `Project accepted CHR evidence into shared test harness`: success.

`src/router_configuration/vendors/mikrotik/chr_test_bridge.py` binds the common assessment to the canonical SHA-256 of the exact CHR acceptance payload.

## Existing live fault evidence reused by the common suite

The common harness also validates and aggregates previously accepted CHR fault evidence instead of rerunning or rewriting those tests:

- DNS failure -> `dns_failure`:
  - source SHA `48aa5ff43dc603f73f41e4db5a1728b4181a4f16`;
  - workflow run `34810824257`;
  - artifact `10334767118`;
  - artifact digest `sha256:b67b44ba776dd2952b47d2ad2ba721043407d6778872a97496ef6fe9a282ae46`.
- upstream Internet blackhole while link remains up -> `wan_failover`:
  - source SHA `bc7054732d07c02303cc9e0dfc01587c4f24fbbf`;
  - workflow run `34809160558`;
  - artifact `10334520218`;
  - artifact digest `sha256:e6682301e9956f8c066af1eae1833e4d650f337cda01809daf62b84450a1299f`.
- owned default-route loss -> `default_route_loss`:
  - source SHA `2a89300e597992b6659d4d49a5c6f0af516ec490`;
  - workflow run `34812460392`;
  - artifact `10335700314`;
  - artifact digest `sha256:ff93f270d3bf6be09933ef1ed01e17b2a44e2bb96e88a8ebb4fd1d9f971f9fe6`.

The strict validators live in `src/router_configuration/vendors/mikrotik/chr_scenario_bridge.py`; multi-scenario aggregation lives in `chr_fault_suite.py`.

A source evidence record that is tampered, weakens a safety flag, changes expected failover/recovery semantics, claims physical acceptance, or no longer matches its accepted schema must fail closed.

## Adding Cisco, Yamaha, Fortinet, TP-Link, or another vendor

Do not duplicate the lab.

For a virtual router/firewall such as an authorized Cisco C8000V, Yamaha vRX, or FortiGate-VM image:

1. keep the image/license outside the repository;
2. add a vendor-isolated boot/identity adapter;
3. attach its NICs to the existing common TAP roles;
4. run the common attachment smoke;
5. declare only verified capabilities in `TestBackendSpec`;
6. reuse external WAN/DNS fault injection where applicable;
7. implement only the vendor-control-plane operations that cannot be common;
8. emit common `ScenarioResult` evidence with the correct fidelity.

For TP-Link Omada Software Controller, classify it as a software-controller backend. Controller/API tests may use the common harness, but forwarding-plane scenarios remain deferred unless a real or suitable virtual gateway backend is available.

## Recovery policy

A hypervisor snapshot is one recovery mechanism, not the definition of rollback correctness.

Vendor-native rollback, configuration restore, transaction rollback, or an external VM checkpoint may each be acceptable when the scenario contract explicitly supports it and the final recovery evidence proves the required state/service restoration.

The test system must never report a recovery PASS merely because a rollback command returned success.

## Non-negotiable boundaries

The reusable lab must never:

- place proprietary images or license keys in repository source control;
- turn a simulator/controller result into vendor-OS evidence;
- turn VM evidence into physical hardware certification;
- inject disruptive faults into a non-disposable target;
- expose a production writer through the common harness;
- assume that one vendor's interface names, management bootstrap, syntax, or rollback mechanism applies to another vendor;
- count deferred hardware tests as PASS.
