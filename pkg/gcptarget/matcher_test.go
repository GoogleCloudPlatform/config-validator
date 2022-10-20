package gcptarget

import (
	"errors"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name    string
		include []string
		exclude []string
		review  interface{}
		want    bool
		wantErr error
	}{
		{
			name:    "include **",
			include: []string{"**"},
			review: map[string]interface{}{
				"ancestry_path": "abc/def",
			},
			want: true,
		},
		{
			name:    "include with *",
			include: []string{"*/def", "*/abc"},
			review: map[string]interface{}{
				"ancestry_path": "abc/def",
			},
			want: true,
		},
		{
			name:    "include not match",
			include: []string{"*/abc"},
			review: map[string]interface{}{
				"ancestry_path": "abc/def",
			},
			want: false,
		},
		{
			name:    "exclude",
			include: []string{"**"},
			exclude: []string{"abc/*"},
			review: map[string]interface{}{
				"ancestry_path": "abc/def",
			},
			want: false,
		},
		{
			name:    "exclude match with **",
			include: []string{"**"},
			exclude: []string{"abc/**"},
			review: map[string]interface{}{
				"ancestry_path": "abc/def/ghi",
			},
			want: false,
		},
		{
			name:    "exclude not match",
			include: []string{"**"},
			exclude: []string{"abc/*"},
			review: map[string]interface{}{
				"ancestry_path": "abc/def/ghi",
			},
			want: true,
		},
		{
			name: "invalid address",
			review: map[string]interface{}{
				"ancestry_path": 123,
			},
			wantErr: ErrInvalidAncestryPath,
		},
		{
			name:    "invalid review object",
			review:  123,
			wantErr: ErrInvalidReview,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matcher := &matcher{
				ancestries:         test.include,
				excludedAncestries: test.exclude,
			}
			got, err := matcher.Match(test.review)
			if got != test.want {
				t.Errorf("Match() = %v, want = %v", got, test.want)
			}
			if !errors.Is(err, test.wantErr) {
				t.Errorf("Match() = %v, want = %v", err, test.wantErr)
			}
		})
	}
}
