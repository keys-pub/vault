package auth

import (
	"bytes"
	"context"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys-ext/auth/fido2"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/vault/auth/api"
	"github.com/pkg/errors"
)

type authDevice struct {
	Device     *fido2.Device
	DeviceInfo *fido2.DeviceInfo
	Auth       *Auth
}

// FIDO2HMACSecret from a device.
type FIDO2HMACSecret struct {
	CredentialID []byte
	Salt         []byte
	AAGUID       string
	NoPin        bool
}

// GenerateFIDO2HMACSecret creates FIDO2 hmac-secret on a device.
func GenerateFIDO2HMACSecret(ctx context.Context, plugin fido2.FIDO2Server, pin string, device string, appName string) (*FIDO2HMACSecret, error) {
	if plugin == nil {
		return nil, errors.Errorf("fido2 plugin not available")
	}

	cdh := bytes.Repeat([]byte{0x00}, 32) // No client data
	rp := &fido2.RelyingParty{
		ID:   "keys.pub",
		Name: "keys.pub",
	}

	logger.Debugf("Find device...")
	dev, err := findDevice(ctx, plugin, device)
	if err != nil {
		return nil, err
	}
	if dev == nil {
		return nil, errors.Errorf("device not found: %s", device)
	}

	userID := keys.Rand16()[:]

	// TODO: Default to using resident key?

	logger.Debugf("Generating hmac-secret...")
	resp, err := plugin.GenerateHMACSecret(ctx, &fido2.GenerateHMACSecretRequest{
		Device:         dev.Device.Path,
		PIN:            pin,
		ClientDataHash: cdh[:],
		RP:             rp,
		User: &fido2.User{
			ID:   userID,
			Name: appName,
		},
		// RK: fido2.True,
	})
	if err != nil {
		return nil, err
	}

	noPin := false
	if pin == "" {
		noPin = true
	}

	salt := keys.Rand32()
	fhs := &FIDO2HMACSecret{
		CredentialID: resp.CredentialID,
		AAGUID:       dev.DeviceInfo.AAGUID,
		Salt:         salt[:],
		NoPin:        noPin,
	}

	return fhs, nil
}

// RegisterFIDO2HMACSecret registers FIDO2HMACSecret.
func (d *DB) RegisterFIDO2HMACSecret(ctx context.Context, plugin fido2.FIDO2Server, hs *FIDO2HMACSecret, mk *[32]byte, pin string) (*Auth, error) {
	if len(hs.CredentialID) < 32 {
		return nil, errors.Errorf("invalid credential id")
	}
	id := encoding.MustEncode(hs.CredentialID, encoding.Base62)
	auth := &Auth{
		ID:        id,
		Type:      api.FIDO2HMACSecretType,
		Salt:      hs.Salt,
		AAGUID:    hs.AAGUID,
		NoPin:     hs.NoPin,
		CreatedAt: time.Now(),
	}

	_, key, err := hmacSecret(ctx, plugin, []*Auth{auth}, pin)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.Errorf("invalid hmac-secret key length")
	}
	auth.EncryptedKey = secretBoxSeal(mk[:], key)
	if err := d.Set(auth); err != nil {
		return nil, err
	}
	return auth, nil
}

// FIDO2HMACSecret authenticates using FIDO2 hmac-secret.
func (d *DB) FIDO2HMACSecret(ctx context.Context, plugin fido2.FIDO2Server, pin string) (*Auth, *[32]byte, error) {
	auths, err := d.ListByType(api.FIDO2HMACSecretType)
	if err != nil {
		return nil, nil, err
	}
	// TODO: How to choose if multiple device matches.
	auth, key, err := hmacSecret(ctx, plugin, auths, pin)
	if err != nil {
		return nil, nil, err
	}
	mk := d.unlock(auth, key)
	return auth, mk, nil
}

func findDevice(ctx context.Context, plugin fido2.FIDO2Server, query string) (*authDevice, error) {
	if plugin == nil {
		return nil, errors.Errorf("fido2 plugin not available")
	}
	devicesResp, err := plugin.Devices(ctx, &fido2.DevicesRequest{})
	if err != nil {
		return nil, err
	}
	for _, device := range devicesResp.Devices {
		if query == "" || device.Path == query || device.Product == query {
			infoResp, err := plugin.DeviceInfo(ctx, &fido2.DeviceInfoRequest{Device: device.Path})
			if err != nil {
				// TODO: Test not a FIDO2 device
				logger.Infof("Failed to get device info: %s", err)
				continue
			}
			return &authDevice{
				Device:     device,
				DeviceInfo: infoResp.Info,
			}, nil
		}
	}
	return nil, nil
}

func matchAAGUID(auths []*Auth, aaguid string) *Auth {
	for _, auth := range auths {
		if auth.AAGUID == aaguid {
			return auth
		}
	}
	return nil
}

// findAuth returns a auth matching the auth credentials (aaguid).
func findAuth(ctx context.Context, plugin fido2.FIDO2Server, auths []*Auth) (*authDevice, error) {
	if auths == nil {
		return nil, errors.Errorf("fido2 plugin not available")
	}
	if len(auths) == 0 {
		return nil, errors.Errorf("no auths specified")
	}

	devicesResp, err := plugin.Devices(ctx, &fido2.DevicesRequest{})
	if err != nil {
		return nil, err
	}
	if len(devicesResp.Devices) == 0 {
		return nil, errors.Errorf("no devices found")
	}

	for _, device := range devicesResp.Devices {
		infoResp, err := plugin.DeviceInfo(ctx, &fido2.DeviceInfoRequest{Device: device.Path})
		if err != nil {
			// TODO: Test not a FIDO2 device
			logger.Infof("Failed to get device info: %s", err)
			continue
		}
		deviceInfo := infoResp.Info
		logger.Debugf("Checking device: %v", deviceInfo)
		if deviceInfo.HasExtension(fido2.HMACSecretExtension) {
			auth := matchAAGUID(auths, deviceInfo.AAGUID)
			if auth != nil {
				logger.Debugf("Found device: %v", device.Path)
				return &authDevice{
					Device:     device,
					DeviceInfo: deviceInfo,
					Auth:       auth,
				}, nil
			}
		}
	}
	return nil, errors.Errorf("no matching devices found")
}

func hmacSecret(ctx context.Context, plugin fido2.FIDO2Server, auths []*Auth, pin string) (*Auth, *[32]byte, error) {
	if plugin == nil {
		return nil, nil, errors.Errorf("fido2 plugin not available")
	}

	logger.Debugf("Looking for device with a matching credential...")
	authDevice, err := findAuth(ctx, plugin, auths)
	if err != nil {
		return nil, nil, err
	}
	if authDevice.Auth == nil {
		return nil, nil, errors.Errorf("device has no matching auth")
	}

	credID, err := encoding.Decode(authDevice.Auth.ID, encoding.Base62)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "credential (provision) id was invalid")
	}

	logger.Debugf("Getting hmac-secret...")
	cdh := bytes.Repeat([]byte{0x00}, 32) // No client data
	rp := &fido2.RelyingParty{
		ID:   "keys.pub",
		Name: "keys.pub",
	}
	secretResp, err := plugin.HMACSecret(ctx, &fido2.HMACSecretRequest{
		Device:         authDevice.Device.Path,
		PIN:            pin,
		ClientDataHash: cdh[:],
		RPID:           rp.ID,
		CredentialIDs:  [][]byte{credID},
		Salt:           authDevice.Auth.Salt,
	})
	if err != nil {
		return nil, nil, err
	}

	if len(secretResp.HMACSecret) != 32 {
		return nil, nil, errors.Errorf("invalid hmac-secret key length")
	}

	return authDevice.Auth, keys.Bytes32(secretResp.HMACSecret), nil
}
