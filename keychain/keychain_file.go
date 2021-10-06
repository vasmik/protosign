package keychain

import (
	"context"
	"fmt"
	"io/ioutil"
	"path"
	"strings"
	"time"
)

type FileProvider struct {
	Path        string
	RefreshRate time.Duration
	data        map[string][]byte
}

func (k *FileProvider) GetPublicKey(ctx context.Context, issuer string) ([]byte, error) {
	val, ok := k.data[issuer]
	if !ok {
		return nil, fmt.Errorf("no data for key %s", issuer)
	}
	return val, nil
}

func (p *FileProvider) Run(ctx context.Context) error {
	if p.RefreshRate == 0 {
		p.RefreshRate = 10 * time.Second
	}
	next := make(chan bool, 1)
	defer close(next)
	next <- true
	ticker := time.NewTicker(p.RefreshRate)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			next <- true
		case <-next:
			if err := p.update(); err != nil {
				return err
			}
		}
	}
}

func (p *FileProvider) update() error {
	files, err := ioutil.ReadDir(p.Path)
	if err != nil {
		return fmt.Errorf("can't read directory: %v", err)
	}
	newVal := make(map[string][]byte)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), "_rsa_public.pem") {
			continue
		}
		key := strings.TrimSuffix(f.Name(), "_rsa_public.pem")
		v, err := ioutil.ReadFile(path.Join(p.Path, f.Name()))
		if err != nil {
			return fmt.Errorf("can't read file: %v", err)
		}
		newVal[key] = v
	}
	p.data = newVal
	return nil
}
