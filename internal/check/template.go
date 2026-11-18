// Package check evaluates the deterministic checks of a project (sql, log,
// expect) through the locks and schedules them. It spends no token.
package check

import "github.com/DavidGodefroid/dutydesk/internal/config"

// MissingFieldError says a template names a field its data does not hold.
type MissingFieldError = config.MissingFieldError

// Render replaces every {name} of tmpl by fields[name]: it is the renderer
// of internal/config, the one the configuration loader validates templates
// with. A name that fields does not hold is a *MissingFieldError.
func Render(tmpl string, fields map[string]string) (string, error) {
	return config.Render(tmpl, fields)
}
