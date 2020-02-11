package gcv

import (
	"context"
	"sync"
	"testing"

	"github.com/pkg/errors"

	"github.com/forseti-security/config-validator/pkg/api/validator"
)

type reviewTestcase struct {
	name        string
	workerCount int
	calls       []reviewCall
}

type reviewCall struct {
	assets             []*validator.Asset // assets to use if not using the default asset set
	scaleFactor        int                // number of copies of asset list to put in one call to Review.
	wantViolationCount int                // the total violation count
	wantError          bool
}

type FakeConfigValidator struct {
	violationMap map[string][]*validator.Violation
}

func NewFakeConfigValidator(violationMap map[string][]*validator.Violation) *FakeConfigValidator {
	for name, violations := range violationMap {
		for _, v := range violations {
			v.Resource = name
		}
	}
	return &FakeConfigValidator{violationMap: violationMap}
}

func (v *FakeConfigValidator) ReviewAsset(ctx context.Context, asset *validator.Asset) ([]*validator.Violation, error) {
	violations, found := v.violationMap[asset.Name]
	if !found {
		return nil, errors.Errorf("name %s not found", asset.Name)
	}
	return violations, nil
}

func TestReview(t *testing.T) {
	// we will run 3x this amount of assets through audit, then reset at end
	// of test.
	var testCases = []reviewTestcase{
		{
			name:        "no assets",
			workerCount: 1,
			calls: []reviewCall{
				{
					assets: []*validator.Asset{},
				},
			},
		},
		{
			name:        "error",
			workerCount: 1,
			calls: []reviewCall{
				{
					assets:    []*validator.Asset{{Name: "invalid name"}},
					wantError: true,
				},
			},
		},
		{
			name:        "single call",
			workerCount: 1,
			calls: []reviewCall{
				{
					assets:             []*validator.Asset{storageAssetNoLogging()},
					wantViolationCount: 2,
				},
			},
		},
		{
			name:        "single call three assets",
			workerCount: 1,
			calls: []reviewCall{
				{
					assets:             defaultReviewTestAssets,
					wantViolationCount: 3,
				},
			},
		},
	}

	var testCase *reviewTestcase
	testCase = &reviewTestcase{
		name:        "128 goroutines x32 calls x16 scale",
		workerCount: 128,
	}
	for i := 0; i < 32; i++ {
		testCase.calls = append(
			testCase.calls,
			reviewCall{
				assets:             defaultReviewTestAssets,
				scaleFactor:        16,
				wantViolationCount: 3,
			},
		)
	}
	testCases = append(testCases, *testCase)
	testCase = &reviewTestcase{
		name:        "single call large scale deadlock test",
		workerCount: 4,
		calls: []reviewCall{
			{
				assets:             defaultReviewTestAssets,
				scaleFactor:        4 * 16,
				wantViolationCount: 3,
			},
		},
	}
	testCases = append(testCases, *testCase)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oldWorkerCount := flags.workerCount
			defer func() {
				flags.workerCount = oldWorkerCount
			}()
			flags.workerCount = tc.workerCount

			stopChannel := make(chan struct{})
			defer close(stopChannel)
			cv := NewFakeConfigValidator(
				map[string][]*validator.Violation{
					"//storage.googleapis.com/my-storage-bucket-with-logging":        nil,
					"//storage.googleapis.com/my-storage-bucket-with-secure-logging": nil,
					"//container.googleapis.com/projects/malaise-forever/zones/us-central1-a/clusters/test-1/k8s/namespaces/whatever": {
						{
							Constraint: "namespace-cost-center-label",
							Message:    "you must provide labels: {\"cost-center\"}",
						},
					},
					"//storage.googleapis.com/my-storage-bucket": {
						{
							Constraint: "require-storage-logging",
							Message:    "//storage.googleapis.com/my-storage-bucket does not have the required logging destination.",
						},
						{
							Constraint: "require-storage-logging-xx",
							Message:    "//storage.googleapis.com/my-storage-bucket does not have the required logging destination.",
						},
					},
				},
			)
			v := NewParallelValidator(stopChannel, cv)

			var groupDone sync.WaitGroup
			for callIdx, call := range tc.calls {
				groupDone.Add(1)
				go func(cIdx int, call reviewCall) {
					defer groupDone.Done()
					if call.scaleFactor == 0 {
						call.scaleFactor = 1
					}

					var assets []*validator.Asset
					for i := 0; i < call.scaleFactor; i++ {
						assets = append(assets, call.assets...)
					}

					result, err := v.Review(context.Background(), &validator.ReviewRequest{
						Assets: assets,
					})
					if call.wantError {
						if err == nil {
							t.Fatal("Expected error, got none")
						}
						return
					} else {
						if err != nil {
							t.Fatalf("review error in call %d: %s", cIdx, err)
						}
					}

					wantViolationCount := call.wantViolationCount * call.scaleFactor
					if len(result.Violations) != wantViolationCount {
						t.Fatalf("wanted %d violations, got %d", wantViolationCount, len(result.Violations))
					}
				}(callIdx, call)
			}
			groupDone.Wait()
		})
	}
}
