# Contributing to InfraGuard Agent

## Branch Strategy
main        — production-ready, protected

develop     — integration branch

feature/*   — new capabilities

fix/*       — bug fixes (auto-created by InfraGuard for remediations)

infraguard/ — autonomous PR branches (created by the agent)

## Commit Convention
feat:     new capability

fix:      bug fix

security: security improvement

docs:     documentation

deploy:   deployment config

refactor: code restructure

## PR Requirements

- All PRs target develop, not main
- InfraGuard agent PRs auto-target main via the remediation engine
- Human PRs require description and checklist completion
