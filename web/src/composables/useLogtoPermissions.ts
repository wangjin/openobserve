// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import { reactive } from "vue";

export type LogtoAction = "read" | "create" | "update" | "delete" | "*";

/**
 * Community Logto permission state for the UI. Mirrors the backend scope
 * snapshot: when Logto is the sole login provider, `feature_permissions` holds
 * `{ feature: [actions] }` derived from the user's scopes; the nav and primary
 * action buttons gate on [`hasFeature`]. When Logto is disabled, `hasFeature`
 * returns `true` so non-Logto deployments are unaffected.
 */
const state = reactive({
  enabled: false,
  permissions: {} as Record<string, LogtoAction[]>,
});

export function setLogtoEnabled(enabled: boolean) {
  state.enabled = !!enabled;
}

export function setFeaturePermissions(fp?: Record<string, LogtoAction[]> | null) {
  state.permissions = fp || {};
}

export function resetFeaturePermissions() {
  state.enabled = false;
  state.permissions = {};
}

/**
 * May the current user use `feature` (optionally a specific `action`)?
 *
 * - Logto disabled → always `true` (community default, no gating).
 * - Logto enabled + feature absent/empty → `false` (deny by default).
 * - Logto enabled + feature has `*` → all actions allowed.
 */
export function hasFeature(feature: string, action?: LogtoAction): boolean {
  if (!state.enabled) return true;
  const actions = state.permissions[feature];
  if (!actions || actions.length === 0) return false;
  if (!action) return true;
  if (actions.includes("*")) return true;
  return actions.includes(action);
}

export function getFeaturePermissions() {
  return state.permissions;
}
