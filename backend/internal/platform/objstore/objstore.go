// Package objstore stores scan artifacts (raw reports, SBOMs) in an
// S3-compatible object store (SeaweedFS by default; AWS S3, Garage, Ceph RGW
// and others work too). Without configuration PATHOS keeps artifacts in
// PostgreSQL instead.
package objstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// MaxObjectSize bounds reads (artifacts are at most 32 MiB uncompressed).
const MaxObjectSize = 64 << 20

// ErrNotFound means the object does not exist.
var ErrNotFound = errors.New("object not found")

// Store is the subset of object storage PATHOS needs.
type Store interface {
	Put(ctx context.Context, key string, body []byte, contentType string) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, keys []string) error
}

// Config selects an S3 endpoint.
type Config struct {
	Endpoint  string // e.g. http://seaweedfs:8333; empty for AWS
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	PathStyle bool // required by most self-hosted stores
}

// S3 implements Store.
type S3 struct {
	c      *s3.Client
	bucket string
}

// NewS3 builds a client. It does not contact the server; call EnsureBucket.
func NewS3(cfg Config) (*S3, error) {
	if cfg.Bucket == "" || cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("object store: bucket, access key and secret key are required")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	creds := aws.Credentials{AccessKeyID: cfg.AccessKey, SecretAccessKey: cfg.SecretKey, Source: "pathos"}
	o := s3.Options{
		Region:       cfg.Region,
		UsePathStyle: cfg.PathStyle,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return creds, nil
		}),
		HTTPClient: &http.Client{Timeout: 2 * time.Minute},
		// Self-hosted stores do not all accept the SDK's default trailing
		// checksums; send them only when an operation requires them.
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	}
	if cfg.Endpoint != "" {
		o.BaseEndpoint = aws.String(cfg.Endpoint)
	}
	return &S3{c: s3.New(o), bucket: cfg.Bucket}, nil
}

// EnsureBucket creates the bucket if it does not exist.
func (s *S3) EnsureBucket(ctx context.Context) error {
	if _, err := s.c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &s.bucket}); err == nil {
		return nil
	}
	_, err := s.c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &s.bucket})
	var owned *types.BucketAlreadyOwnedByYou
	var exists *types.BucketAlreadyExists
	if err != nil && !errors.As(err, &owned) && !errors.As(err, &exists) {
		return fmt.Errorf("create bucket %s: %w", s.bucket, err)
	}
	return nil
}

// AccessError is an object store answer that refuses the credential
// (HTTP 401 or 403).
type AccessError struct {
	Status int
	Err    error
}

func (e *AccessError) Error() string {
	return fmt.Sprintf("object store denied access (HTTP %d)", e.Status)
}
func (e *AccessError) Unwrap() error { return e.Err }

// Ping checks the bucket is reachable and readable with the configured
// credentials (HeadBucket; nothing is created or written).
func (s *S3) Ping(ctx context.Context) error {
	_, err := s.c.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &s.bucket})
	if err == nil {
		return nil
	}
	var re interface{ HTTPStatusCode() int }
	if errors.As(err, &re) {
		switch code := re.HTTPStatusCode(); code {
		case http.StatusUnauthorized, http.StatusForbidden:
			return &AccessError{Status: code, Err: err}
		case http.StatusNotFound:
			return fmt.Errorf("bucket %s: %w", s.bucket, ErrBucketNotFound)
		}
	}
	return err
}

// ErrBucketNotFound means the configured bucket does not exist.
var ErrBucketNotFound = errors.New("bucket not found")

// Put implements Store.
func (s *S3) Put(ctx context.Context, key string, body []byte, contentType string) error {
	_, err := s.c.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &s.bucket, Key: &key, Body: bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))), ContentType: &contentType,
	})
	return err
}

// Get implements Store.
func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	out, err := s.c.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	var nf *types.NoSuchKey
	if errors.As(err, &nf) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	b, err := io.ReadAll(io.LimitReader(out.Body, MaxObjectSize+1))
	if err == nil && len(b) > MaxObjectSize {
		return nil, errors.New("object exceeds the size limit")
	}
	return b, err
}

// PutStream uploads size bytes from body. The body must be seekable so the
// SDK can sign and retry the request (callers stream large objects through a
// temporary file).
func (s *S3) PutStream(ctx context.Context, key string, body io.ReadSeeker, size int64, contentType string) error {
	_, err := s.c.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &s.bucket, Key: &key, Body: body,
		ContentLength: aws.Int64(size), ContentType: &contentType,
	})
	return err
}

// GetStream returns the object body without buffering or a size limit; the
// caller must close it.
func (s *S3) GetStream(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := s.c.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	var nf *types.NoSuchKey
	if errors.As(err, &nf) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return out.Body, nil
}

// Exists reports whether the object exists.
func (s *S3) Exists(ctx context.Context, key string) (bool, error) {
	_, err := s.c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &s.bucket, Key: &key})
	if err == nil {
		return true, nil
	}
	var nf *types.NotFound
	var nsk *types.NoSuchKey
	if errors.As(err, &nf) || errors.As(err, &nsk) {
		return false, nil
	}
	return false, err
}

// Delete implements Store (batches of 1000; missing keys are not errors).
func (s *S3) Delete(ctx context.Context, keys []string) error {
	for len(keys) > 0 {
		n := min(len(keys), 1000)
		objs := make([]types.ObjectIdentifier, 0, n)
		for _, k := range keys[:n] {
			objs = append(objs, types.ObjectIdentifier{Key: aws.String(k)})
		}
		out, err := s.c.DeleteObjects(ctx, &s3.DeleteObjectsInput{Bucket: &s.bucket, Delete: &types.Delete{Objects: objs, Quiet: aws.Bool(true)}})
		if err != nil {
			return err
		}
		if len(out.Errors) > 0 {
			e := out.Errors[0]
			return fmt.Errorf("delete %s: %s", aws.ToString(e.Key), aws.ToString(e.Message))
		}
		keys = keys[n:]
	}
	return nil
}

// Load returns an artifact's bytes from its object key, or the inline copy
// when the row was stored in the database.
func Load(ctx context.Context, store Store, key *string, inline []byte) ([]byte, error) {
	if key == nil {
		return inline, nil
	}
	if store == nil {
		return nil, errors.New("artifact is in object storage, but no object store is configured")
	}
	return store.Get(ctx, *key)
}

// Memory is an in-process Store for tests.
type Memory struct{ M map[string][]byte }

// NewMemory returns an empty store.
func NewMemory() *Memory { return &Memory{M: map[string][]byte{}} }

func (m *Memory) Put(_ context.Context, key string, body []byte, _ string) error {
	m.M[key] = bytes.Clone(body)
	return nil
}

func (m *Memory) Get(_ context.Context, key string) ([]byte, error) {
	b, ok := m.M[key]
	if !ok {
		return nil, ErrNotFound
	}
	return b, nil
}

func (m *Memory) Delete(_ context.Context, keys []string) error {
	for _, k := range keys {
		delete(m.M, k)
	}
	return nil
}
