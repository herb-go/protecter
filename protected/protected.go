package protected

import (
	"net/http"
	"strings"
	"sync"

	"github.com/herb-go/protecter"
)

type Protected struct {
	Key        protecter.Key
	locker     sync.Mutex
	protecters map[string]*protecter.Protecter
	handlers   sync.Map
}

func (p *Protected) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Path
	if string(u[0]) == "/" {
		u = u[1:]
	}
	plist := strings.SplitN(u, "/", 2)
	if len(plist) < 2 {
		plist = append(plist, "")
	}
	if plist[0] == "" {
		http.Error(w, http.StatusText(404), 404)
		return
	}
	action, ok := p.handlers.Load(plist[0])
	if ok == false {
		http.Error(w, http.StatusText(404), 404)
		return
	}
	r.URL.Path = "/" + plist[1]
	action.(http.Handler).ServeHTTP(w, r)
}

func (p *Protected) Reset() {
	p.locker.Lock()
	defer p.locker.Unlock()
	p.protecters = map[string]*protecter.Protecter{}
	p.handlers.Range(func(key interface{}, value interface{}) bool {
		p.handlers.Delete(key)
		return true
	})
}
func (p *Protected) ResetProtecters() {
	p.locker.Lock()
	defer p.locker.Unlock()
	p.protecters = map[string]*protecter.Protecter{}

}
func (p *Protected) SetProtecter(name string, protecter *protecter.Protecter) {
	p.locker.Lock()
	defer p.locker.Unlock()
	if name != "" {
		if name[0] == '/' {
			name = name[1:]
		}
	}
	p.protecters[name] = protecter
}

func (p *Protected) handle(name string, h http.HandlerFunc) {
	if name != "" {
		if name[0] == '/' {
			name = name[1:]
		}
	}
	p.handlers.Store(name, h)

}
func (p *Protected) Handle(name string, h http.HandlerFunc) {
	p.locker.Lock()
	defer p.locker.Unlock()
	p.handle(
		name,
		p.Key.ProtectWith(
			p.protecters[name],
			h,
		).ServeHTTP,
	)
}

func (p *Protected) HandleProtected(name string, protected *Protected) {
	p.locker.Lock()
	defer p.locker.Unlock()
	p.handle(name, protected.ServeHTTP)
}

func (p *Protected) Unhandle(name string) {
	p.handlers.Delete(name)
}

func New() *Protected {
	return &Protected{}
}

var Channels = New()

var DefaultCannelsPrefix = "/channels"
