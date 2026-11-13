package amqpx

import (
	"encoding/base64"
	"fmt"
	"math"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// ToTable converts free-form JSON (as decoded into map[string]any) into an
// AMQP field table. Integral numbers become int32 when they fit (RabbitMQ
// expects that for most x-arguments) and int64 otherwise; other numbers
// become float64; objects become nested tables; arrays become field arrays.
func ToTable(m map[string]any) (amqp.Table, error) {
	if len(m) == 0 {
		return nil, nil
	}
	t := amqp.Table{}
	for k, v := range m {
		fv, err := toField(v)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", k, err)
		}
		t[k] = fv
	}
	return t, nil
}

func toField(v any) (any, error) {
	switch x := v.(type) {
	case nil, bool, string, int32, int64:
		return x, nil
	case int:
		return intField(int64(x)), nil
	case float64:
		if x == math.Trunc(x) && !math.IsInf(x, 0) && math.Abs(x) < 1<<53 {
			return intField(int64(x)), nil
		}
		return x, nil
	case float32:
		return float64(x), nil
	case map[string]any:
		return ToTable(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			fv, err := toField(e)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			out[i] = fv
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported value type %T", v)
}

func intField(n int64) any {
	if n >= math.MinInt32 && n <= math.MaxInt32 {
		return int32(n)
	}
	return n
}

// FromTable converts an AMQP field table into JSON-friendly values: byte
// arrays become base64 strings, timestamps RFC 3339 strings and decimals
// floating-point numbers.
func FromTable(t amqp.Table) map[string]any {
	if len(t) == 0 {
		return nil
	}
	out := make(map[string]any, len(t))
	for k, v := range t {
		out[k] = fromField(v)
	}
	return out
}

func fromField(v any) any {
	switch x := v.(type) {
	case amqp.Table:
		m := FromTable(x)
		if m == nil {
			m = map[string]any{}
		}
		return m
	case map[string]any:
		return FromTable(amqp.Table(x))
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = fromField(e)
		}
		return out
	case []byte:
		return base64.StdEncoding.EncodeToString(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339)
	case amqp.Decimal:
		return float64(x.Value) / math.Pow10(int(x.Scale))
	}
	return v
}
