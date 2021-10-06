package keychain

import (
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3Provider struct {
	Bucket      string
	Path        string
	RefreshRate time.Duration
	client      *s3.Client
	data        map[string][]byte
}

func (k *S3Provider) GetPublicKey(ctx context.Context, issuer string) ([]byte, error) {
	val, ok := k.data[issuer]
	if !ok {
		return nil, fmt.Errorf("no data for key %s", issuer)
	}
	return val, nil
}

func (p *S3Provider) Run(ctx context.Context) error {
	if p.RefreshRate == 0 {
		p.RefreshRate = 10 * time.Second
	}
	if p.client == nil {
		cfg, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			return err
		}
		p.client = s3.NewFromConfig(cfg)
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
			if err := p.update(ctx); err != nil {
				return err
			}
		}
	}
}

func (p *S3Provider) update(ctx context.Context) error {
	pref := p.Path + "/"
	input := &s3.ListObjectsV2Input{Bucket: &p.Bucket, Prefix: &pref}
	out, err := p.client.ListObjectsV2(ctx, input)
	if err != nil {
		return fmt.Errorf("can't list S3 bucket: %v", err)
	}
	newVal := make(map[string][]byte)
	for _, obj := range out.Contents {
		if !strings.HasSuffix(*obj.Key, "_rsa_public.pem") {
			continue
		}
		s3object := &s3.GetObjectInput{Bucket: &p.Bucket, Key: obj.Key}
		out, err := p.client.GetObject(ctx, s3object)
		if err != nil {
			return fmt.Errorf("can't load key file `s3://%s/%s`: %v", p.Bucket, *obj.Key, err)
		}
		data, err := ioutil.ReadAll(out.Body)
		if err != nil {
			return fmt.Errorf("can't read key file `s3://%s/%s`: %v", p.Bucket, *obj.Key, err)
		}
		key := strings.TrimSuffix(*obj.Key, "_rsa_public.pem")
		key = strings.TrimPrefix(key, pref)
		newVal[key] = data
	}
	p.data = newVal
	return nil
}
