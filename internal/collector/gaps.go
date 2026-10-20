package collector

import (
	"errors"
	"fmt"

	"github.com/locktivity/epack/componentsdk"
)

// Artifact paths in the pack.
const (
	detailedPath   = "artifacts/okta.json"
	idpPosturePath = "artifacts/okta.idp-posture.json"
)

// gapLog records each value the collector leaves out of the detailed
// artifact in the run's recorder.
type gapLog struct {
	rec *componentsdk.Recorder
}

func newGapLog(rec *componentsdk.Recorder) *gapLog {
	if rec == nil {
		rec = &componentsdk.Recorder{}
	}
	return &gapLog{rec: rec}
}

func detailed(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: detailedPath, Pointer: pointer}
}

// failure is an error that leaves values out, with the warning the collector
// wrote for it and the scope to grant, which every gap it leaves carries.
type failure struct {
	err     error
	warning string
	missing string
}

func (f *failure) Error() string { return f.err.Error() }
func (f *failure) Unwrap() error { return f.err }

// failed returns err with its warning and, when there is one, the scope to
// grant.
func failed(err error, warning, missing string) error {
	return &failure{err: err, warning: warning, missing: missing}
}

// gapOptions returns the warning and the scope to grant that err carries.
func gapOptions(err error) []componentsdk.GapOption {
	var f *failure
	if !errors.As(err, &f) {
		return nil
	}
	opts := []componentsdk.GapOption{componentsdk.Warning(f.warning)}
	if f.missing != "" {
		opts = append(opts, componentsdk.MissingPermission(f.missing))
	}
	return opts
}

// notCollected records the detailed values at pointers as left out because
// of err.
func (l *gapLog) notCollected(err error, pointers ...string) {
	l.rec.Helper()
	opts := gapOptions(err)
	for _, pointer := range pointers {
		l.rec.NotCollected(detailed(pointer), err, opts...)
	}
}

// partial records the detailed rollups at pointers as left out because
// unmeasured of the items they cover could not be read, err being one of the
// failures.
func (l *gapLog) partial(unmeasured int, err error, pointers ...string) {
	l.rec.Helper()
	opts := gapOptions(err)
	for _, pointer := range pointers {
		l.rec.Partial(detailed(pointer), unmeasured, err, opts...)
	}
}

// notLicensed records the detailed value at pointer as left out because the
// org lacks the feature, with the warning the collector wrote for it.
func (l *gapLog) notLicensed(pointer, detail, warning string) {
	l.rec.Helper()
	l.rec.NotCollectedCode(detailed(pointer), componentsdk.CodeNotLicensed, detail, componentsdk.Warning(warning))
}

// mirror records at a normalized value the gap that covers the detailed
// value it copies, if any.
func (l *gapLog) mirror(fromPointer, toPointer string) {
	l.rec.Mirror(detailed(fromPointer), componentsdk.Location{Path: idpPosturePath, Pointer: toPointer})
}

// rowPointer addresses a field of one row of an array in the detailed
// artifact.
func rowPointer(array string, index int, field string) string {
	return fmt.Sprintf("%s/%d/%s", array, index, field)
}

// firstError returns the first non-nil error.
func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
