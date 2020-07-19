package cache

import (
	"sync"
	"time"
)

const (
	DefaultExpiration time.Duration = 0
	NoExpiration      time.Duration = -1
)

type Item struct {
	value      interface{}
	expiration int64
}

type TTLCache struct {
	items      sync.Map
	defaultTTL time.Duration
	lookupFunc func(interface{}) (interface{}, bool)
}

func NewTTLCache(defaultTTL time.Duration) *TTLCache {
	c := &TTLCache{defaultTTL: defaultTTL}

	// GC
	go func() {
		interval := c.defaultTTL / 2
		if interval < time.Second {
			interval = time.Second
		}

		for now := range time.Tick(interval) {
			c.items.Range(func(key, val interface{}) bool {
				item := val.(*Item)
				if item.expiration > 0 && now.UnixNano() > item.expiration {
					c.Del(key)
				}
				return true
			})
		}
	}()

	return c
}

func (c *TTLCache) Get(key interface{}) (interface{}, bool) {
	val, ok := c.items.Load(key)
	if !ok && c.lookupFunc != nil {
		return c.lookupFunc(key)
	}

	item, ok := val.(*Item)
	if !ok {
		return nil, false
	}

	return item.value, ok
}

func (c *TTLCache) GetAndResetExpiration(key interface{}, ttl time.Duration) (interface{}, bool) {
	val, ok := c.Get(key)
	if ok {
		c.SetWithExpiration(key, val, ttl)
	}

	return val, ok
}

func (c *TTLCache) Set(key, val interface{}) {
	c.SetWithExpiration(key, val, c.defaultTTL)
}

func (c *TTLCache) SetWithExpiration(key, val interface{}, ttl time.Duration) {
	var expiration int64

	switch {
	case ttl == 0:
		expiration = time.Now().Add(c.defaultTTL).UnixNano()
	case ttl >= 1:
		expiration = time.Now().Add(ttl).UnixNano()
	}

	item := &Item{val, expiration}
	c.items.Store(key, item)
}

func (c *TTLCache) Del(key interface{}) {
	c.items.Delete(key)
}

func (c *TTLCache) SetLookupFunc(fn func(interface{}) (interface{}, bool)) {
	c.lookupFunc = fn
}
