package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestStoreCreateAndListScans(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	users, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) == 0 {
		t.Fatal("expected default admin user")
	}

	id := NewID("scan")
	scan, err := s.CreateScan(ctx, id, CreateScanInput{
		UserID: users[0].ID,
		Target: "https://example.com",
		Status: ScanStatusPending,
	})
	if err != nil {
		t.Fatal(err)
	}
	if scan.ID != id {
		t.Fatalf("unexpected id %s", scan.ID)
	}

	if err := s.UpdateScan(ctx, id, UpdateScanInput{
		Status:       ScanStatusCompleted,
		RiskLevel:    "high",
		FindingCount: 3,
		HighCount:    2,
		Finished:     true,
	}); err != nil {
		t.Fatal(err)
	}

	items, err := s.ListScans(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Status != ScanStatusCompleted {
		t.Fatalf("unexpected scans: %+v", items)
	}
}

func TestGetUserByAPIKey(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	user, err := s.CreateUser(ctx, "ci-bot", NewAPIKey())
	if err != nil {
		t.Fatal(err)
	}
	found, err := s.GetUserByAPIKey(ctx, user.APIKey)
	if err != nil {
		t.Fatal(err)
	}
	if found.ID != user.ID {
		t.Fatalf("user mismatch")
	}
}
