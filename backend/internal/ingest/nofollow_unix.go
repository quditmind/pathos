//go:build unix

package ingest

import "syscall"

// oNoFollow refuses a symlink as the final path component.
const oNoFollow = syscall.O_NOFOLLOW
