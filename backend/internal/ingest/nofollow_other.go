//go:build !unix

package ingest

// oNoFollow is not available here; O_EXCL and os.Root still prevent
// writing through links.
const oNoFollow = 0
