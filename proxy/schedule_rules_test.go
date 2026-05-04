package proxy

import (
	"testing"
	"time"
)

func TestScheduleRulesAllowOnlyInsideWindows(t *testing.T) {
	rules, err := NewScheduleRules([]ScheduleWindow{
		{Profile: "students", Days: []string{"mon", "wed"}, Start: "08:30", End: "16:00"},
	})
	if err != nil {
		t.Fatalf("NewScheduleRules() error = %v", err)
	}
	inside := time.Date(2026, 5, 4, 9, 0, 0, 0, time.Local) // Monday
	outsideHour := time.Date(2026, 5, 4, 17, 0, 0, 0, time.Local)
	outsideDay := time.Date(2026, 5, 5, 9, 0, 0, 0, time.Local) // Tuesday
	if !rules.Allowed("students", inside) {
		t.Fatal("Allowed(students, inside) = false, want true")
	}
	if rules.Allowed("students", outsideHour) {
		t.Fatal("Allowed(students, outsideHour) = true, want false")
	}
	if rules.Allowed("students", outsideDay) {
		t.Fatal("Allowed(students, outsideDay) = true, want false")
	}
	if !rules.Allowed("staff", outsideDay) {
		t.Fatal("Allowed(staff without windows) = false, want true")
	}
}

func TestScheduleRulesRejectInvalidWindow(t *testing.T) {
	_, err := NewScheduleRules([]ScheduleWindow{
		{Profile: "bad", Days: []string{"noday"}, Start: "09:00", End: "10:00"},
	})
	if err == nil {
		t.Fatal("NewScheduleRules() error = nil, want error")
	}
	_, err = NewScheduleRules([]ScheduleWindow{
		{Profile: "bad", Days: []string{"mon"}, Start: "10:00", End: "09:00"},
	})
	if err == nil {
		t.Fatal("NewScheduleRules() error = nil, want end-after-start error")
	}
}
