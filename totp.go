package totp

import (
	"bytes"
	"image/png"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	period = 30
)

var cfg *Config

type Config struct {
	Issuer string `validate:"required"`
	Width  int    `validate:"required"`
	Height int    `validate:"required"`
}

func Init(config *Config) {
	cfg = config
}

func Generate(username string) (qr []byte, secret string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      cfg.Issuer,
		AccountName: username,
		Digits:      otp.DigitsSix,
		Period:      0,
		SecretSize:  0,
		Secret:      nil,
		Algorithm:   0,
		Rand:        nil,
	})
	if err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer

	img, err := key.Image(cfg.Width, cfg.Height)
	if err != nil {
		return nil, "", err
	}

	err = png.Encode(&buf, img)
	if err != nil {
		return nil, "", err
	}

	return buf.Bytes(), key.Secret(), nil
}

func Validate(code, secret string) bool {
	otpOk, err := totp.ValidateCustom(
		code,
		secret,
		time.Now().UTC(),
		totp.ValidateOpts{
			Period:    period,
			Skew:      0,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
	if err != nil {
		otpOk = false
	}

	return otpOk
}
