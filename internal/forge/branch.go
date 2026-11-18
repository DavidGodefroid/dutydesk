package forge

import (
	"regexp"
	"strings"
)

var branchRE = regexp.MustCompile(`^dutydesk/[a-z0-9][a-z0-9._-]{0,80}$`)

const maxSlug = 48

// BranchName builds the branch of a proposal: BranchName("INC-000123",
// "Fix the stuck job") is "dutydesk/inc-000123-fix-the-stuck-job". The result
// always satisfies the branch rule enforced by Propose.
func BranchName(incidentID, title string) string {
	id := slug(incidentID, 24)
	if id == "" {
		id = "inc"
	}
	if s := slug(title, maxSlug); s != "" {
		return "dutydesk/" + id + "-" + s
	}
	return "dutydesk/" + id
}

// slug lowercases s and keeps runs of [a-z0-9] joined by single dashes.
func slug(s string, max int) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		} else {
			dash = true
		}
		if b.Len() >= max {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

func validBranch(name string) bool {
	return branchRE.MatchString(name) && validRefName(name)
}
