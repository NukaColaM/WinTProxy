# Remove Capture Config Settings

## Goal

Remove the user-facing `capture` configuration section and the associated queue tuning parameters. WinDivert queue behavior should use internal constants instead of config-file fields so users only see meaningful traffic, proxy, DNS, bypass, policy, and logging settings.

## What I Already Know

* User request: the current config exposes `capture` settings that should not be exposed to users.
* User request: the capture parameters are unnecessary and should be removed rather than hidden behind undocumented config.
* `config.example.json`, `README.md`, and `guide.md` currently document `capture` as a top-level section.
* `src/app/config.c` currently parses `capture.queue_length`, `capture.queue_time_ms`, and `capture.queue_size` and includes `capture` in strict top-level validation.
* `inc/app/config.h` carries `capture_config_t` inside `app_config_t`.
* `src/divert/adapter.c` reads queue settings from `engine->config->capture`, with fallbacks to WinDivert constants.
* Backend spec says unknown config keys should fail validation and `_comment` keys are the only documented exception.

## Requirements

* Remove the `capture` section from public config examples and documentation.
* Remove parsing/validation support for top-level `capture` and its queue parameters.
* Remove the capture config data model from `app_config_t`.
* Use internal/default WinDivert queue constants directly when opening/configuring the adapter queue.
* Keep strict config validation: a user-supplied top-level `capture` key should now be rejected as an unknown key.
* Keep runtime behavior otherwise unchanged for DNS, bypass, policy, proxy, logging, and adapter startup.

## Acceptance Criteria

* [x] `config.example.json` no longer contains a top-level `capture` object or queue tuning comments.
* [x] `README.md` and `guide.md` no longer list `capture` as a public config section.
* [x] `config_load()` no longer accepts or parses `capture`.
* [x] `app_config_t` no longer contains capture queue fields.
* [x] `divert/adapter.c` still applies queue length/time/size using internal constants.
* [x] The project builds successfully.

## Definition of Done

* Code and docs updated consistently.
* Build completes with the existing CMake/MinGW setup.
* No unrelated behavior changes.
* Spec update considered after implementation.

## Technical Approach

Remove the capture config surface completely rather than preserving a compatibility shim. This matches the existing strict schema contract: unknown config keys fail validation instead of being silently ignored. Adapter queue settings remain internal implementation details sourced from constants.

## Decision (ADR-lite)

**Context**: Capture queue settings are implementation tuning knobs, not product-level traffic behavior. Exposing them in the config adds noise and invites users to tune parameters that are not needed.

**Decision**: Delete the public `capture` config section and remove the associated fields/parser. Keep the WinDivert queue settings as internal defaults.

**Consequences**: Existing configs that still include `capture` will fail strict validation and should remove that section. Runtime queue behavior remains the same default behavior.

## Out of Scope

* Changing the actual WinDivert queue constant values.
* Adding new CLI flags or environment variables for queue tuning.
* Relaxing strict config validation for legacy config compatibility.

## Technical Notes

* Relevant code/docs inspected: `inc/app/config.h`, `src/app/config.c`, `src/divert/adapter.c`, `config.example.json`, `README.md`, `guide.md`.
* Relevant specs: `.trellis/spec/backend/index.md`, `.trellis/spec/backend/directory-structure.md`, `.trellis/spec/backend/logging-guidelines.md`, `.trellis/spec/backend/quality-guidelines.md`.
