# ADR 0003: bind analysis inputs before adding an executor

Status: proposed; implemented as a library prerequisite, pending independent review.

## Problem

Local patch validation and separate provider fixture tests do not establish that a returned plan
corresponds to the source, state, finding and policy used to prepare a candidate. Legacy resource
source changes also replace the rule, introducing a disruption question that local HCL cannot answer.

## Decision

Add immutable Git-object source capture, a versioned confidential input manifest, completion
integrity/freshness checks, and a conservative policy for pinned Terraform/provider plan JSON.
Keep source-only update and replacement-review outcomes distinct. Never interpret a hash,
caller-supplied timestamp or local `can_open_pr` as production authorization.

Expected input metadata crosses a trusted internal coordinator boundary. The API cannot assert it.
An executor-produced envelope is likewise trusted internal evidence, not arbitrary uploaded JSON.
The first implementation consumes such envelopes in library tests and synthetic provider CI.
No production acquisition, sandbox executor, publisher or cloud mutation is added.

## Alternatives and consequences

Running Terraform in the API would combine untrusted intake with executable configuration and
provider code. Adding a process timeout without sandboxing would not isolate credentials, mounts or
network. Treating all source changes as in-place would hide the pinned legacy replacement behavior.
Signing caller-created hashes would authenticate a signer without proving authorized acquisition.

The selected contract permits testing scope/integrity independently of AWS credentials and runtime
deployment. It also favors false negatives: roots with modules, aliases, indexed resources, arbitrary
expression resolution and unsupported tool versions are rejected for the target. Root modules with
child modules are rejected. An executor/controller must still
provide authenticated inputs and attest their use. See [bound-analysis.md](../bound-analysis.md).
