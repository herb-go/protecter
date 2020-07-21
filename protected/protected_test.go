package protected

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/herb-go/protecter"
)

var testHanlder = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(r.URL.Path))
})

func TestChannel(t *testing.T) {
	p := New()
	var req *http.Request
	var err error
	p.Reset()
	defer p.Reset()
	Channels.Reset()
	defer Channels.Reset()
	p.SetProtecter("never", protecter.ForbiddenProtecter)
	p.SetProtecter("/always", protecter.NotWorkingProtecter)
	p.Handle("/never", testHanlder)
	p.Handle("always", testHanlder)
	s := httptest.NewServer(p)
	defer s.Close()
	req, err = http.NewRequest("GET", s.URL+"/always/test", nil)
	if err != nil {
		panic(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	if string(data) != "/test" {
		t.Fatal(string(data))
	}
	if resp.StatusCode != 200 {
		t.Fatal(resp)
	}

	req, err = http.NewRequest("GET", s.URL+"/always", nil)
	if err != nil {
		panic(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	data, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	if string(data) != "/" {
		t.Fatal(string(data))
	}
	if resp.StatusCode != 200 {
		t.Fatal(resp)
	}

	req, err = http.NewRequest("GET", s.URL+"/", nil)
	if err != nil {
		panic(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal(resp)
	}

	req, err = http.NewRequest("GET", s.URL+"/notexist", nil)
	if err != nil {
		panic(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal(resp)
	}

	req, err = http.NewRequest("GET", s.URL+"/never", nil)
	if err != nil {
		panic(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal(resp)
	}

	req, err = http.NewRequest("GET", s.URL+"/never/test", nil)
	if err != nil {
		panic(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal(resp)
	}

	p.Unhandle("always")
	req, err = http.NewRequest("GET", s.URL+"/always", nil)
	if err != nil {
		panic(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal(resp)
	}
	Channels.SetProtecter("/testchannel", protecter.NotWorkingProtecter)
	Channels.Handle("testchannel", testHanlder)
	p.HandleProtected(DefaultCannelsPrefix, Channels)

	req, err = http.NewRequest("GET", s.URL+DefaultCannelsPrefix+"/testchannel", nil)
	if err != nil {
		panic(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp)
	}
	Channels.ResetProtecters()
	Channels.Handle("testchannel", testHanlder)
	req, err = http.NewRequest("GET", s.URL+DefaultCannelsPrefix+"/testchannel", nil)
	if err != nil {
		panic(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal(resp)
	}

}
