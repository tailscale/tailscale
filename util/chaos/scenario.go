package chaos

import (
	"fmt"
	"log"

	"tailscale.com/util/multierr"
)

type Scenario struct {
	// BeforeSteps and AfterSteps are run before any step and after all steps.
	BeforeSteps func() error
	AfterSteps  func() error

	// BeforeStep and AfterStep are run before and after each step, respectively.
	// Can be used to start a profiling of control for a given step.
	BeforeStep func() error
	AfterStep  func() error

	// Steps to run in order.
	Steps []Step

	// TearDown is run after all steps are run, regardless of success or failure.
	TearDown func() error

	// ContinueOnError, if true, will continue to run steps even if one fails.
	ContinueOnError bool
}

type Step struct {
	Run func() error

	// BeforeStep and AfterStep are run before and after the step.
	// Can be used to start a profiling of control for a given step.
	BeforeStep func() error
	AfterStep  func() error
}

func (s *Scenario) Run() (err error) {
	defer func() {
		if s.TearDown != nil {
			terr := s.TearDown()
			if terr != nil {
				err = fmt.Errorf("TearDown: %w", terr)
			}
		}
	}()
	if s.BeforeSteps != nil {
		if err := s.BeforeSteps(); err != nil {
			return fmt.Errorf("BeforeSteps: %w", err)
		}
	}
	var errs []error
	for _, step := range s.Steps {
		if s.BeforeStep != nil {
			if err := s.BeforeStep(); err != nil {
				return fmt.Errorf("Before each step: %w", err)
			}
		}
		if step.BeforeStep != nil {
			if err := step.BeforeStep(); err != nil {
				return fmt.Errorf("BeforeStep %w", err)
			}
		}
		if err := step.Run(); err != nil {
			log.Printf("Step failed: %s", err)
			errs = append(errs, err)
			if !s.ContinueOnError {
				break
			}
		}
		if step.AfterStep != nil {
			if err := step.AfterStep(); err != nil {
				return fmt.Errorf("AfterStep: %w", err)
			}
		}

		if s.AfterStep != nil {
			if err := s.AfterStep(); err != nil {
				return fmt.Errorf("After each step: %w", err)
			}
		}
	}
	if s.AfterSteps != nil {
		if err := s.AfterSteps(); err != nil {
			return fmt.Errorf("AfterSteps: %w", err)
		}
	}

	return multierr.New(errs...)
}
