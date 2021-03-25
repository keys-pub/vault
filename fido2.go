package vault

import (
	"context"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys-ext/auth/fido2"
	"github.com/keys-pub/vault/auth"
	"github.com/pkg/errors"
)

// SetFIDO2Plugin sets the plugin.
func (v *Vault) SetFIDO2Plugin(fido2Plugin fido2.FIDO2Server) {
	v.fido2Plugin = fido2Plugin
}

// FIDO2Devices lists FIDO2 devices.
func (v *Vault) FIDO2Devices(ctx context.Context) ([]*fido2.Device, error) {
	if v.fido2Plugin == nil {
		return nil, errors.Errorf("no fido2 plugin set")
	}
	resp, err := v.fido2Plugin.Devices(ctx, &fido2.DevicesRequest{})
	if err != nil {
		return nil, err
	}
	return resp.Devices, nil
}

// GenerateFIDO2HMACSecret ...
func (v *Vault) GenerateFIDO2HMACSecret(ctx context.Context, pin string, device string, appName string) (*auth.FIDO2HMACSecret, error) {
	if v.fido2Plugin == nil {
		return nil, errors.Errorf("no fido2 plugin set")
	}
	return auth.GenerateFIDO2HMACSecret(ctx, v.fido2Plugin, pin, device, appName)
}

// SetupFIDO2HMACSecret sets up vault with a FIDO2 hmac-secret.
func (v *Vault) SetupFIDO2HMACSecret(ctx context.Context, hs *auth.FIDO2HMACSecret, pin string, opt ...SetupOption) (*[32]byte, error) {
	if v.fido2Plugin == nil {
		return nil, errors.Errorf("no fido2 plugin set")
	}
	mk := keys.Rand32()
	_, err := v.auth.RegisterFIDO2HMACSecret(ctx, v.fido2Plugin, hs, mk, pin)
	if err != nil {
		return nil, err
	}
	if err := v.Setup(mk, opt...); err != nil {
		return nil, err
	}
	return mk, nil
}

// RegisterFIDO2HMACSecret adds vault with a FIDO2 hmac-secret.
// Requires recent Unlock.
func (v *Vault) RegisterFIDO2HMACSecret(ctx context.Context, hs *auth.FIDO2HMACSecret, pin string) error {
	if v.mk == nil {
		return ErrLocked
	}
	if v.fido2Plugin == nil {
		return errors.Errorf("no fido2 plugin set")
	}
	_, err := v.auth.RegisterFIDO2HMACSecret(ctx, v.fido2Plugin, hs, v.mk, pin)
	if err != nil {
		return err
	}
	return nil
}

// UnlockWithFIDO2HMACSecret opens vault with a FIDO2 hmac-secret.
func (v *Vault) UnlockWithFIDO2HMACSecret(ctx context.Context, pin string) (*[32]byte, error) {
	_, mk, err := v.auth.FIDO2HMACSecret(ctx, v.fido2Plugin, pin)
	if err != nil {
		return nil, err
	}
	if err := v.Unlock(mk); err != nil {
		return nil, err
	}
	return mk, nil
}
