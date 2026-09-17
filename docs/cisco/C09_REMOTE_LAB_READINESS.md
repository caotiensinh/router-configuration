# Cisco C09 Remote Lab Readiness

## Purpose

The GitHub self-hosted runner is an orchestrator for C09. It is not required to
own `/dev/kvm`, install QEMU/libvirt, or host the Catalyst 8000V VM locally.

`c09_remote_lab_readiness.py` provides the fail-closed bridge from an accepted
C09 lab-execution boundary to a separately administered remote virtualization
host. The bridge performs readiness discovery only. It does not start a VM,
upload an image, execute an IOS XE change, or grant production write authority.

## Why the remote-host path exists

The approved self-hosted runner may legitimately have restricted host
privileges. C09 must not weaken that runner's OS security merely to gain KVM or
Docker access. A remote lab host keeps the GitHub runner bounded to orchestration
while virtualization privileges remain on a lab-specific system.

## Required upstream boundary

The probe accepts only an immutable `cisco-c09-lab-execution-boundary/1` record
that is already:

- bound to the exact source Git SHA;
- bound to an accepted C08 approval decision;
- admitted as a Catalyst 8000V router;
- restricted to a disposable virtual-appliance lab;
- restricted to the canonical C09 scenarios;
- non-production and non-physical;
- unable to carry production write authority.

A digest mismatch or any self-promoted completion/write claim fails closed.

## Opaque lab-host contract

`build_remote_lab_host_contract()` binds the C09 boundary to:

- an opaque `lab_host_id`;
- an allowed provider (`qemu_kvm` or `proxmox_qemu`);
- a detached host attestation SHA-256.

The contract never records the SSH hostname/IP, username, credentials, private
keys, tokens, or Cisco license material.

## SSH trust boundary

The readiness probe requires OpenSSH with all of the following properties:

- `BatchMode=yes`;
- `StrictHostKeyChecking=yes`;
- an explicitly supplied trusted `known_hosts` file;
- password and keyboard-interactive authentication disabled;
- forwarding, agent forwarding, X11 forwarding, and local commands disabled;
- a bounded connection timeout.

The trusted host key must come from an approved out-of-band identity source. Do
not bootstrap trust by accepting an unverified first-contact key in the same run.

The optional SSH identity file is runtime-only and is never included in the
sanitized readiness record.

## Fixed read-only probe

The remote command is fixed by repository code and checks only:

- `/dev/kvm` exists;
- the remote account can read and write `/dev/kvm`;
- CPU VMX/SVM exposure is visible;
- `qemu-system-x86_64` is present;
- `qemu-img` is present;
- optional `virsh` availability;
- optional libvirt socket availability.

No package installation, service modification, image upload, VM start, network
mutation, or IOS XE command is allowed in this readiness stage.

A remote host becomes `ready_for_c8000v_image_staging=true` only when KVM is
usable and both required QEMU tools are present. This readiness result does not
complete C09 and earns no acceptance points by itself.

## Runtime inputs

The CLI uses runtime environment variables rather than command-line secrets:

- `C09_REMOTE_LAB_HOST`
- `C09_REMOTE_LAB_USER`
- `C09_REMOTE_LAB_PORT` (optional, default `22`)
- `C09_REMOTE_LAB_KNOWN_HOSTS_FILE`
- `C09_REMOTE_LAB_IDENTITY_FILE` (optional when an approved SSH agent/config is used)

The host contract JSON path is the only positional CLI argument.

Example invocation shape:

```text
python -m router_configuration.vendors.cisco.c09_remote_lab_readiness <host-contract.json>
```

Do not commit runtime endpoint data, private keys, passwords, Cisco images, or
license/entitlement material to the repository.

## Sanitized result

The output records capability booleans, an opaque lab-host ID, immutable contract
digest, and a coarse SSH failure class when needed. It intentionally excludes the
remote endpoint, SSH username, raw stderr, and credentials.

It always keeps:

- `mutation_attempted=false`;
- `image_started=false`;
- `live_execution_observed=false`;
- `c09_complete=false`;
- `physical_hardware_claimed=false`;
- `production_writer_available=false`;
- `production_write_authorized=false`.

## Next boundary

Only after this readiness record passes may a later C09 image-staging/lifecycle
component be considered. That later component must continue to bind the exact
C08/C09 evidence chain and must never embed Cisco proprietary images or licensing
material in the repository.
