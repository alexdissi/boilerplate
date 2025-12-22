package storage

import "fmt"

type Factory struct{}

func NewFactory() *Factory {
	return &Factory{}
}

func (f *Factory) Create(config ProviderConfig) (Storage, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	switch c := config.(type) {
	case *R2Config:
		return NewR2Storage(*c)
	default:
		return nil, fmt.Errorf("unsupported config type: %T", config)
	}
}
