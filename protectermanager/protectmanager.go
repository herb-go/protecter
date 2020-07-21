package protectermanager

import (
	"sync"

	"github.com/herb-go/protecter"
)

var locker sync.Mutex

var protecters = map[string]*protecter.Protecter{}

func Register(name string) *protecter.Protecter {
	locker.Lock()
	defer locker.Unlock()
	p, ok := protecters[name]
	if !ok {
		p = protecter.New()
		protecters[name] = p
	}
	return p
}

func Names() []string {
	locker.Lock()
	defer locker.Unlock()
	result := []string{}
	for k := range protecters {
		result = append(result, k)
	}
	return result
}

func Flush() {
	locker.Lock()
	defer locker.Unlock()
	protecters = map[string]*protecter.Protecter{}
}

func Reset() {
	locker.Lock()
	defer locker.Unlock()
	for k := range protecters {
		protecters[k].Reset()
	}
}
