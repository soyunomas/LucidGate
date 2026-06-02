package proxy

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

type asyncRecord struct {
	level slog.Level
	msg   string
	attrs []slog.Attr
}

// AsyncHandler wraps slog.Handler to route logs via an asynchronous, bounded queue
// to eliminate disk I/O latency from hot network relay transaction paths.
type AsyncHandler struct {
	queue    chan asyncRecord
	handler  slog.Handler
	dropped  atomic.Uint64
	sinkName string
	quit     chan struct{}
}

func NewAsyncHandler(h slog.Handler, cap int, sinkName string) *AsyncHandler {
	ah := &AsyncHandler{
		queue:    make(chan asyncRecord, cap),
		handler:  h,
		sinkName: sinkName,
		quit:     make(chan struct{}),
	}
	go ah.worker()
	return ah
}

func (ah *AsyncHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return ah.handler.Enabled(ctx, level)
}

func (ah *AsyncHandler) Handle(ctx context.Context, r slog.Record) error {
	select {
	case <-ah.quit:
		return nil
	default:
	}

	var attrs []slog.Attr
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	rec := asyncRecord{
		level: r.Level,
		msg:   r.Message,
		attrs: attrs,
	}

	select {
	case ah.queue <- rec:
	case <-ah.quit:
	default:
		ah.dropped.Add(1)
		DroppedLogsTotal.WithLabelValues(ah.sinkName).Inc()
	}
	return nil
}

func (ah *AsyncHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &AsyncHandler{
		queue:    ah.queue,
		handler:  ah.handler.WithAttrs(attrs),
		sinkName: ah.sinkName,
		quit:     ah.quit,
	}
}

func (ah *AsyncHandler) WithGroup(name string) slog.Handler {
	return &AsyncHandler{
		queue:    ah.queue,
		handler:  ah.handler.WithGroup(name),
		sinkName: ah.sinkName,
		quit:     ah.quit,
	}
}

func (ah *AsyncHandler) worker() {
	for {
		select {
		case rec := <-ah.queue:
			r := slog.NewRecord(time.Now(), rec.level, rec.msg, 0)
			r.AddAttrs(rec.attrs...)
			_ = ah.handler.Handle(context.Background(), r)
		case <-ah.quit:
			// Drain remaining logs in queue
			for {
				select {
				case rec := <-ah.queue:
					r := slog.NewRecord(time.Now(), rec.level, rec.msg, 0)
					r.AddAttrs(rec.attrs...)
					_ = ah.handler.Handle(context.Background(), r)
				default:
					return
				}
			}
		}
	}
}

// Close drains the queue and stops the handler safely.
func (ah *AsyncHandler) Close() {
	close(ah.quit)
}
