package goauth

import (
	"time"

	"github.com/go-redis/redis"
)

type redisStoreAssistant struct {
	redisDb *redis.Client
}

func (r *redisStoreAssistant) SetValue(key string, value string, duration time.Duration) error {
	return r.redisDb.Set(key, value, duration).Err()
}

func (r *redisStoreAssistant) GetValue(key string) (string, error) {
	getResult := r.redisDb.Get(key)
	err := getResult.Err()
	if err != nil {
		return "", err
	}
	return getResult.Val(), nil
}

func (r *redisStoreAssistant) DeleteValue(key string) error {
	return r.redisDb.Del(key).Err()
}

// NewRedisStoreAssistant creates a StoreAssistant from an existing Redis client.
func NewRedisStoreAssistant(redisDb *redis.Client) StoreAssistant {
	return &redisStoreAssistant{redisDb: redisDb}
}
