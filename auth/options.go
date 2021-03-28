package auth

import "github.com/keys-pub/keys"

// Options for auth.
type Options struct {
	ClientKey *keys.EdX25519Key
}

// Option for DB.
type Option func(*Options)

func newOptions(opts ...Option) *Options {
	options := &Options{}
	for _, o := range opts {
		o(options)
	}
	return options
}

// WithClientKey ...
func WithClientKey(key *keys.EdX25519Key) Option {
	return func(o *Options) {
		o.ClientKey = key
	}
}
