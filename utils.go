/*
 * Copyright (c) 2020 Percipia
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Contributor(s):
 * Andrew Querol <aquerol@percipia.com>
 */
package eslgo

import (
	"fmt"
	"strings"
)

// BuildVars - A helper that builds channel variable strings to be included in various commands to FreeSWITCH.
// WARNING: values are NOT fully escaped. Characters with special meaning in FreeSWITCH variable syntax
// (comma ",", brackets "{}[]<>", equals "=") are not sanitized. Callers must ensure values do not
// contain these characters when they originate from untrusted input, or injection into originate
// arguments may occur. A proper escaping implementation should be added before using user-provided data.
func BuildVars(format string, vars map[string]string) string {
	// No vars do not format
	if len(vars) == 0 {
		return ""
	}

	var builder strings.Builder
	for key, value := range vars {
		if builder.Len() > 0 {
			builder.WriteString(",")
		}
		builder.WriteString(key)
		builder.WriteString("=")
		if strings.ContainsAny(value, " ") {
			builder.WriteString("'")
			builder.WriteString(value)
			builder.WriteString("'")
		} else {
			builder.WriteString(value)
		}
	}
	return fmt.Sprintf(format, builder.String())
}
