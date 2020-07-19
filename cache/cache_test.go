package cache

import (
	"testing"
	"time"
)

func TestSetAndGet(t *testing.T) {
	ttlCache := NewTTLCache(NoExpiration)
	ttlCache.Set("key1", 1)

	if val, ok := ttlCache.Get("key1"); !ok {
		t.Errorf("The value for the key 'key1' should be nil, but was '%v'", val)
	} else {
		if intVal, ok := val.(int); !ok || intVal != 1 {
			t.Errorf("The value for the key 'key1' should be '1', but was '%v'", val)
		}
	}

	if val, ok := ttlCache.Get("key2"); ok {
		t.Errorf("The value for the key 'key2' should be nil, but was '%v'", val)
	}
}

func TestSetAndExpire(t *testing.T) {
	ttlCache := NewTTLCache(NoExpiration)
	ttlCache.SetWithExpiration("key1", 1, 1*time.Second)
	ttlCache.SetWithExpiration("key2", 2, 3*time.Second)

	time.Sleep(2 * time.Second)

	if val, ok := ttlCache.Get("key1"); ok {
		t.Errorf("The value for the key 'key1' should be nil, but was '%v'", val)
	}

	if _, ok := ttlCache.Get("key2"); !ok {
		t.Errorf("The value for the key 'key2' should be nil, but was not")
	}
}

func TestLookupFunc(t *testing.T) {
	ttlCache := NewTTLCache(NoExpiration)
	ttlCache.SetLookupFunc(func(key interface{}) (interface{}, bool) {
		switch key.(type) {
		case string:
			return key, true
		default:
			return nil, false
		}

	})

	if val, ok := ttlCache.Get(1); ok {
		t.Errorf("The value for the key 1 should be nil but was '%v'", val)
	}

	if val, ok := ttlCache.Get("key1"); !ok {
		t.Errorf("The value for the key 'key1' should be 'key1', but was '%v'", val)
	} else {
		if stringVal, ok := val.(string); !ok || stringVal != "key1" {
			t.Errorf("The value for the key 'key1' should be 'key1', but was '%v'", val)
		}
	}
}
