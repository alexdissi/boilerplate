package storage

import (
	"context"
	"io"
)

type Storage interface {
	Download(ctx context.Context, objectKey string) (io.ReadCloser, error)
	Delete(ctx context.Context, objectKey string) error
}

type ProviderConfig interface {
	Validate() error
}
