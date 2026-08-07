/**
 * Compile-time contract assertions.
 *
 * scripts/check-api-contract.py proves the running server provides what
 * docs/openapi.yaml requires. That catches the server drifting away from the
 * spec, but not the direction that actually bit us: the admin UI referencing a
 * field nobody has. `haproxy_ssl` was bound to a routing toggle, type-checked
 * cleanly against a hand-written interface, and silently did nothing.
 *
 * These assertions close that direction. If a hand-written type declares a field
 * the specification does not, `npm run typecheck` fails and names the field.
 *
 * This file emits no runtime code; it exists purely for the type checker.
 */
import type { components } from './generated'
import type { GlobalRouting, Thresholds, SlackConfig } from './types'
import type { TimingTokenConfig } from './client'

type Spec = components['schemas']

/** Field names present on T but absent from the specification. */
type Undocumented<T, S> = Exclude<keyof T, keyof S>

/**
 * Resolves to `true` when every field of T is documented. Otherwise it resolves
 * to a tuple naming the offenders, so the compiler error points at the field
 * rather than just saying "not assignable".
 */
type AllDocumented<T, S> = [Undocumented<T, S>] extends [never]
  ? true
  : ['undocumented field(s) - add them to docs/openapi.yaml or remove them', Undocumented<T, S>]

// Each line fails to compile if the hand-written type invents a field.
export const _routingIsDocumented: AllDocumented<GlobalRouting, Spec['GlobalRouting']> = true
export const _timingIsDocumented: AllDocumented<TimingTokenConfig, Spec['TimingTokenConfig']> = true
export const _thresholdsAreDocumented: AllDocumented<Thresholds, Spec['Thresholds']> = true
export const _slackIsDocumented: AllDocumented<SlackConfig, Spec['SlackConfig']> = true
