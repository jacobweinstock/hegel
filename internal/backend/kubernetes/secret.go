package kubernetes

import (
	"context"
	"errors"
	"fmt"

	"github.com/tinkerbell/hegel/internal/frontend/secret"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	encryptionKeyStringDataKey = "encryption_key"
	secretStringDataKey        = "secret"
)

func (b *Backend) GetSecret(ctx context.Context, ip string) (secret.Data, error) {
	hw, err := b.retrieveByIP(ctx, ip)
	if err != nil {
		return secret.Data{}, err
	}

	// Look up the secret specified in the Hardware object.
	if hw.Spec.Metadata == nil && hw.Spec.Metadata.Secret == nil {
		return secret.Data{}, errors.New("secret data not specified in Hardware object")
	}

	allSecrets := ""
	for _, s := range hw.Spec.Metadata.Secret.Secrets {
		// Return the secret data.
		sd := &v1.Secret{}
		sdKey := types.NamespacedName{Namespace: s.Namespace, Name: s.Name}

		if err := b.client.Get(ctx, sdKey, sd); err != nil {
			return secret.Data{}, fmt.Errorf("failed to retrieve secret data: %w", err)
		}
		allSecrets += string(sd.Data[secretStringDataKey])
	}

	encryption := secret.Encryption{}
	if hw.Spec.Metadata != nil && hw.Spec.Metadata.Secret != nil && hw.Spec.Metadata.Secret.Encryption != nil {
		encryption.Strategy = secret.EncryptionStrategy(hw.Spec.Metadata.Secret.Encryption.Strategy)
		if hw.Spec.Metadata.Secret.Encryption.Algorithm != "" && hw.Spec.Metadata.Secret.Encryption.KeyRef.Name != "" {
			// get the secret key.
			sk := &v1.Secret{}
			skKey := types.NamespacedName{Namespace: hw.Spec.Metadata.Secret.Encryption.KeyRef.Namespace, Name: hw.Spec.Metadata.Secret.Encryption.KeyRef.Name}
			if err := b.client.Get(ctx, skKey, sk); err != nil {
				return secret.Data{}, fmt.Errorf("failed to retrieve secret key: %w", err)
			}
			encryption = secret.Encryption{
				Algorithm: hw.Spec.Metadata.Secret.Encryption.Algorithm,
				Key:       string(sk.Data[encryptionKeyStringDataKey]),
				Strategy:  secret.EncryptionStrategy(hw.Spec.Metadata.Secret.Encryption.Strategy),
			}
		}
	}

	return secret.Data{Secret: allSecrets, Encryption: encryption}, nil
}
