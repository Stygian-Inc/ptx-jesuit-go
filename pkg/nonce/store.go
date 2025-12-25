package nonce

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type NonceStore struct {
	client *redis.Client
}

func NewNonceStore(url string) (*NonceStore, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opts)
	return &NonceStore{client: client}, nil
}

func (s *NonceStore) CheckAndSetNonce(nonce string, expirationTimestamp int64) (bool, error) {
	ctx := context.Background()

	// Set with expiration (SETNX)
	now := time.Now().Unix()
	if expirationTimestamp < now {
		return false, nil // Already expired
	}

	ttl := time.Duration(expirationTimestamp-now) * time.Second

	// SetNX returns true if key was set (new), false if it existed
	isNew, err := s.client.SetNX(ctx, nonce, "1", ttl).Result()
	if err != nil {
		return false, err
	}

	return isNew, nil
}

func (s *NonceStore) Close() error {
	return s.client.Close()
}
