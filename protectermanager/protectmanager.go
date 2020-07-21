package protectermanager

import (
	"fmt"
	"sync"

	"github.com/herb-go/protecter"
)

var Debug bool
var locker sync.Mutex

var protecters = map[string]*protecter.Protecter{}

func Register(name string) *protecter.Protecter {
	locker.Lock()
	defer locker.Unlock()
	p, ok := protecters[name]
	if !ok {
		p = protecter.New()
		protecters[name] = p
		if Debug {
			fmt.Printf("Protecteer [%s] registered\n", name)
		}
	}
	return p
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
