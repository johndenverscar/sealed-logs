// Package stream is the live-tail path: the collector publishes every sealed
// chunk it stores to one Kafka topic, and the aggregator reads it for tails. The
// topic carries exactly what the bucket does, so it holds no plaintext either.
package stream

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"

	"sealedlogs/internal/config"
)

const Topic = "sealed-chunks"

// Message is one stored chunk: where it lives in the bucket and the stored body
// itself ({meta, sealed}).
type Message struct {
	ObjectKey string          `json:"object_key"`
	Chunk     json.RawMessage `json:"chunk"`
}

func Brokers() []string { return strings.Split(config.KafkaBrokers, ",") }

func NewClient(opts ...kgo.Opt) (*kgo.Client, error) {
	return kgo.NewClient(append([]kgo.Opt{kgo.SeedBrokers(Brokers()...)}, opts...)...)
}

// EnsureTopic creates the topic with one partition, so a tail sees chunks in the
// order they were stored.
func EnsureTopic(ctx context.Context, cl *kgo.Client) error {
	_, err := kadm.NewClient(cl).CreateTopic(ctx, 1, 1, nil, Topic)
	if errors.Is(err, kerr.TopicAlreadyExists) {
		return nil
	}
	return err
}

// EndOffsets is where a new reader should start to see only what comes next.
func EndOffsets(ctx context.Context, cl *kgo.Client) (map[string]map[int32]kgo.Offset, error) {
	ends, err := kadm.NewClient(cl).ListEndOffsets(ctx, Topic)
	if err != nil {
		return nil, err
	}
	out := map[string]map[int32]kgo.Offset{Topic: {}}
	var lerr error
	ends.Each(func(o kadm.ListedOffset) {
		if o.Err != nil {
			lerr = o.Err
			return
		}
		out[Topic][o.Partition] = kgo.NewOffset().At(o.Offset)
	})
	return out, lerr
}
