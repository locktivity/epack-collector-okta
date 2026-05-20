package collector

import "github.com/locktivity/epack/componentsdk"

// normalizeForLevel ensures every level-gated array is non-nil when collecting
// at that level. The per-surface collectors are intentionally nil-preserving (so
// trust output emits `null` for audit/internal fields rather than misleading
// empty arrays); this pass flips nil→[] for audit/internal fields once those
// levels are active.
//
// Contract:
//   - trust: audit/internal fields emit as `null` ("not collected").
//   - audit: audit fields emit as `[]` or `[...]`; internal fields stay `null`.
//   - internal: both audit and internal fields emit as `[]` or `[...]`.
func normalizeForLevel(p *OrgPosture, level componentsdk.Level) {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return
	}

	if p.Posture.PerFactorType == nil {
		p.Posture.PerFactorType = []FactorTypeCount{}
	}
	if p.Users.Inventory == nil {
		p.Users.Inventory = []User{}
	}
	if p.Apps.Inventory == nil {
		p.Apps.Inventory = []App{}
	}
	if p.PrivilegedAccess.Inventory == nil {
		p.PrivilegedAccess.Inventory = []PrivilegedUser{}
	}
	if p.PrivilegedAccess.CustomRoles == nil {
		p.PrivilegedAccess.CustomRoles = []CustomRole{}
	}
	if p.Policy.Policies == nil {
		p.Policy.Policies = []PolicySummary{}
	}
	if p.DeviceAccess.Policies == nil {
		p.DeviceAccess.Policies = []DeviceAssurancePolicySummary{}
	}

	if !level.AtLeast(componentsdk.LevelInternal) {
		return
	}
}
