package enterprise

import (
	"context"
	"time"
)

type Scheduler struct {
	service  *Service
	interval time.Duration
}

func NewScheduler(service *Service, interval time.Duration) *Scheduler {
	if interval <= 0 {
		interval = time.Minute
	}
	return &Scheduler{service: service, interval: interval}
}

func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	s.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

func (s *Scheduler) tick(ctx context.Context) {
	s.service.ProcessPending(ctx)
	_ = s.service.ProcessSchedules(ctx)
}
