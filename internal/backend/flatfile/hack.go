package flatfile

import (
	"context"
	"errors"

	"github.com/tinkerbell/hegel/internal/frontend/hack"
	"github.com/tinkerbell/hegel/internal/frontend/secret"
)

// GetHackInstance exists to satisfy the hack.Client interface. It is not implemented.
func (b *Backend) GetHackInstance(context.Context, string) (hack.Instance, error) {
	return hack.Instance{}, errors.New("unsupported")
}

func (b *Backend) GetSecret(ctx context.Context, ip string) (secret.Data, error) {
	return secret.Data{}, errors.New("unsupported")
}
