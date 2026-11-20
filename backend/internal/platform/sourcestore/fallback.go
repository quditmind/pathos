package sourcestore

import (
	"context"
	"errors"
	"io"
)

// Fallback writes to Primary and reads from Primary, then from Secondary
// when Primary does not have the object.
//
// It keeps an installation's data readable when object storage is enabled
// after the start: uploads, source snapshots and Human Eye evidence written
// before then stay in the encrypted directory store (the `sources` volume),
// while PATHOS_S3_BUCKET switches every new object to S3. Without the
// fallback, every repository imported before the switch failed to scan
// ("snapshot download failed: worker API returned 500", sourcestore: object
// not found). Objects keep their key in both stores, and each store
// encrypts with a key-bound data key, so nothing needs re-encrypting.
type Fallback struct {
	Primary   Store
	Secondary Store
}

// Put implements Store: new objects go to the primary store only.
func (f Fallback) Put(ctx context.Context, key string, r io.Reader) (int64, error) {
	return f.Primary.Put(ctx, key, r)
}

// Open implements Store.
func (f Fallback) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	rc, err := f.Primary.Open(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return f.Secondary.Open(ctx, key)
	}
	return rc, err
}

// Delete implements Store: the object is removed from both stores.
func (f Fallback) Delete(ctx context.Context, keys ...string) error {
	return errors.Join(f.Primary.Delete(ctx, keys...), f.Secondary.Delete(ctx, keys...))
}

// Exists implements Store.
func (f Fallback) Exists(ctx context.Context, key string) (bool, error) {
	ok, err := f.Primary.Exists(ctx, key)
	if err != nil || ok {
		return ok, err
	}
	return f.Secondary.Exists(ctx, key)
}
