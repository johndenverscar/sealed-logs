// Package scan reads storage the way an attacker with the bucket and ClickHouse
// would, and counts sensitive strings it can see.
package scan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"sealedlogs/internal/config"
)

var Needles = [][]byte{
	[]byte("4111 1111 1111 1111"),
	[]byte("4111111111111111"),
	[]byte("my social is"),
	[]byte("payment captured"),
	[]byte("trace=t_"),
}

type Result struct {
	Objects, ObjectHits, Rows, RowHits int
}

func (r Result) String() string {
	return fmt.Sprintf("object store: %d objects, %d hits · ClickHouse: %d rows, %d hits", r.Objects, r.ObjectHits, r.Rows, r.RowHits)
}

// Run scans everything. extra adds needles, such as the exact text of a traced line.
func Run(ctx context.Context, extra ...[]byte) (Result, error) {
	var r Result
	needles := append(append([][]byte{}, Needles...), extra...)
	mc, err := minio.New(config.MinioEndpoint, &minio.Options{Creds: credentials.NewStaticV4(config.MinioUser, config.MinioPass, "")})
	if err != nil {
		return r, err
	}
	for o := range mc.ListObjects(ctx, config.Bucket, minio.ListObjectsOptions{Recursive: true}) {
		if o.Err != nil {
			return r, o.Err
		}
		obj, err := mc.GetObject(ctx, config.Bucket, o.Key, minio.GetObjectOptions{})
		if err != nil {
			return r, err
		}
		b, err := io.ReadAll(obj)
		obj.Close()
		if err != nil {
			return r, err
		}
		r.Objects++
		r.ObjectHits += count(b, needles)
	}

	q := url.Values{"query": {"SELECT * FROM sealed.log_chunks FORMAT TSV"}, "user": {config.CHUser}, "password": {config.CHPass}}
	resp, err := http.Get(config.CHHTTP + "/?" + q.Encode())
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return r, err
	}
	if resp.StatusCode != 200 {
		return r, fmt.Errorf("clickhouse %d: %s", resp.StatusCode, b)
	}
	r.Rows = bytes.Count(b, []byte("\n"))
	r.RowHits = count(b, needles)
	return r, nil
}

func count(b []byte, needles [][]byte) int {
	n := 0
	for _, x := range needles {
		if len(x) == 0 {
			continue
		}
		n += bytes.Count(b, x)
	}
	return n
}
