package chaos

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestScenario(t *testing.T) {
	tests := []struct {
		name         string
		scenarioFunc func() ([]int, error)
		want         []int
	}{
		{
			name: "scenario-only-step",
			scenarioFunc: func() ([]int, error) {
				var got []int
				s := Scenario{
					Steps: []Step{
						{
							Run: func() error {
								got = append(got, 1)
								return nil
							},
						},
					},
				}
				return got, s.Run()
			},
			want: []int{1},
		},
		{
			name: "scenario-only-steps",
			scenarioFunc: func() ([]int, error) {
				var got []int
				s := Scenario{
					Steps: []Step{
						{
							Run: func() error {
								got = append(got, 1)
								return nil
							},
						},
						{
							Run: func() error {
								got = append(got, 2)
								return nil
							},
						},
					},
				}
				return got, s.Run()
			},
			want: []int{1, 2},
		},
		{
			name: "scenario-everything",
			scenarioFunc: func() ([]int, error) {
				var got []int
				s := Scenario{
					BeforeSteps: func() error {
						got = append(got, 1)
						return nil
					},
					BeforeStep: func() error {
						got = append(got, 2)
						return nil
					},
					Steps: []Step{
						{
							Run: func() error {
								got = append(got, 3)
								return nil
							},
						},
						{
							BeforeStep: func() error {
								got = append(got, 4)
								return nil
							},
							Run: func() error {
								got = append(got, 5)
								return nil
							},
							AfterStep: func() error {
								got = append(got, 6)
								return nil
							},
						},
					},
					AfterStep: func() error {
						got = append(got, 7)
						return nil
					},
					AfterSteps: func() error {
						got = append(got, 8)
						return nil
					},
					TearDown: func() error {
						got = append(got, 9)
						return nil
					},
				}
				return got, s.Run()
			},
			want: []int{1, 2, 3,
				// "out of order" is expected as this
				// is the AfterStep and BeforeStep called
				// for each function
				7, 2,
				4, 5, 6, 7, 8, 9},
		},
		// TODO(kradalby): Add test cases for errors and continueOnError
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.scenarioFunc()
			if err != nil {
				t.Errorf("scenarioFunc() error = %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("unexpected scenario order (-want +got):\n%s", diff)
			}
		})
	}
}
