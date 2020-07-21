package protecter

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/herb-go/herbsecurity/authority"
)

func TestContext(t *testing.T) {
	storemiddleware := func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		DefaultKey.StoreAuth(r, authority.NewAuth("test"))
		DefaultKey.StoreProtecter(r, NotWorkingProtecter)
		next(w, r)
	}
	action := func(w http.ResponseWriter, r *http.Request) {
		storemiddleware(w, r, func(w http.ResponseWriter, r *http.Request) {
			p := DefaultKey.LoadProtecter(r)
			if p != NotWorkingProtecter {
				panic(errors.New("worng protecter"))
			}
			w.Write([]byte(DefaultKey.LoadAuth(r).Principal()))
		})
	}
	s := httptest.NewServer(http.HandlerFunc(action))
	defer s.Close()
	resp, err := http.Get(s.URL)
	if err != nil {
		panic(err)
	}
	if resp.StatusCode != 200 {
		t.Fatal(resp)
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	if string(data) != "test" {
		t.Fatal(string(data))
	}
}
