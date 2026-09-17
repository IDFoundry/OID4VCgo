// Package conformancesuite drives the OpenID Foundation conformance
// suite's own REST API (POST /api/plan, POST /api/runner, GET
// /api/info/{id}) — generic to the suite itself, with no OID4VCI- or
// FAPI-specific content. Ported near-verbatim from FAPIgo's own
// cmd/conformance-client/suite.go, which established this same
// pattern for FAPI2 client certification against the identical suite.
// Shared by every driver binary in this repo that calls the suite as
// an outbound HTTP client (cmd/conformance-wallet,
// conformance/issuer/scripts/run-fapi2sp-battery) so this protocol
// handling exists once, not once per binary.
package conformancesuite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// SuitePlan is the minimal shape a driver needs back from POST
// /api/plan — the plan's id, and every module the plan wants run, in
// the order the suite itself lists them.
type SuitePlan struct {
	ID      string       `json:"id"`
	Modules []PlanModule `json:"modules"`
}

// PlanModule is one entry of a created plan's own module list — the
// suite lists every module/variant crossing the plan enumerates, so
// Variant is what actually distinguishes one crossing from another
// when TestModule repeats.
type PlanModule struct {
	TestModule string            `json:"testModule"`
	Variant    map[string]string `json:"variant"`
}

// SuiteModule is the minimal shape a driver needs back from POST
// /api/runner: the module's own id, and the base URL
// (https://.../test/a/<alias>) its discovery document, authorization
// endpoint, etc. all live under.
type SuiteModule struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// CreatePlan creates a new conformance-suite test plan for planName
// (with any [variant=value] selectors already embedded, matching how
// run-test-plan.py's own CLI syntax works), posting configJSON as the
// plan configuration body, and returns the new plan's id and the full
// module list it wants run, in the suite's own order.
func CreatePlan(httpClient *http.Client, apiBase, planName string, variant map[string]string, configJSON []byte) (string, []PlanModule, error) {
	q := url.Values{}
	q.Set("planName", planName)
	if len(variant) > 0 {
		variantJSON, err := json.Marshal(variant)
		if err != nil {
			return "", nil, fmt.Errorf("marshal variant: %w", err)
		}
		q.Set("variant", string(variantJSON))
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"api/plan?"+q.Encode(), bytes.NewReader(configJSON))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	body, status, err := Do(httpClient, req)
	if err != nil {
		return "", nil, err
	}
	if status != http.StatusCreated {
		return "", nil, fmt.Errorf("create plan: unexpected status %d: %s", status, body)
	}
	var plan SuitePlan
	if err := json.Unmarshal(body, &plan); err != nil {
		return "", nil, fmt.Errorf("decode plan response: %w", err)
	}
	return plan.ID, plan.Modules, nil
}

// CreateModuleInstance creates one test module instance within planID
// and returns its id and base URL. variant must repeat the exact
// resolved variant map the plan's own module list entry already fixed
// for testName (PlanModule.Variant) — confirmed live: POST /api/runner
// does not infer it from plan+test alone when a plan's module list
// enumerates more than one variant crossing for the same testName,
// rejecting the request with "Missing value for required variant
// parameter" for every axis it can't resolve on its own otherwise.
func CreateModuleInstance(httpClient *http.Client, apiBase, planID, testName string, variant map[string]string) (SuiteModule, error) {
	q := url.Values{}
	q.Set("test", testName)
	q.Set("plan", planID)
	if len(variant) > 0 {
		variantJSON, err := json.Marshal(variant)
		if err != nil {
			return SuiteModule{}, fmt.Errorf("marshal variant: %w", err)
		}
		q.Set("variant", string(variantJSON))
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"api/runner?"+q.Encode(), nil)
	if err != nil {
		return SuiteModule{}, err
	}

	body, status, err := Do(httpClient, req)
	if err != nil {
		return SuiteModule{}, err
	}
	if status != http.StatusCreated {
		return SuiteModule{}, fmt.Errorf("create module instance: unexpected status %d: %s", status, body)
	}
	var module SuiteModule
	if err := json.Unmarshal(body, &module); err != nil {
		return SuiteModule{}, fmt.Errorf("decode module response: %w", err)
	}
	return module, nil
}

// ModuleInfo is the minimal shape a driver needs from GET
// /api/info/{id} — the module's current lifecycle status, and its
// graded result once that status is final. Result is meaningless while
// Status isn't yet FINISHED or INTERRUPTED — the suite leaves a stale
// default in that field until then.
type ModuleInfo struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

// FetchModuleInfo does a single, un-polled GET /api/info/{moduleID}.
func FetchModuleInfo(httpClient *http.Client, apiBase, moduleID string) (ModuleInfo, error) {
	req, err := http.NewRequest(http.MethodGet, apiBase+"api/info/"+moduleID, nil)
	if err != nil {
		return ModuleInfo{}, err
	}
	body, status, err := Do(httpClient, req)
	if err != nil {
		return ModuleInfo{}, err
	}
	if status != http.StatusOK {
		return ModuleInfo{}, fmt.Errorf("get info: unexpected status %d", status)
	}
	var info ModuleInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return ModuleInfo{}, err
	}
	return info, nil
}

// WaitUntilWaiting polls GET /api/info/{moduleID} until the module
// reaches WAITING, the state in which it's actually ready to receive a
// driving client's first request. A module instance is not immediately
// usable right after creation — the suite still has async setup to do
// (server configuration, JWKS generation) — and firing a request at it
// too early doesn't just fail harmlessly: the module treats the
// unexpected early arrival as if it belonged to a later step, gets
// stuck (INTERRUPTED with "Illegal test state change"), and can never
// recover for the rest of its run (the same failure mode FAPIgo's own
// cmd/conformance-client discovered driving an analogous suite plan).
// Only relevant to a driver that itself plays the client — a driver
// whose module instances are entirely driven by the suite's own
// browser automation has nothing to gate on WAITING for.
func WaitUntilWaiting(httpClient *http.Client, apiBase, moduleID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		info, err := FetchModuleInfo(httpClient, apiBase, moduleID)
		if err == nil {
			if info.Status == "WAITING" {
				return nil
			}
			// A module can fail during its own async setup (bad
			// config, an eagerly-checked cert, ...) before ever
			// reaching WAITING at all — surface that immediately
			// rather than waiting out the full timeout only to
			// report a misleading "did not reach WAITING".
			if info.Status == "INTERRUPTED" || info.Status == "FINISHED" {
				return fmt.Errorf("module %s reached %s (result=%s) before ever becoming WAITING — check %sapi/log/%s", moduleID, info.Status, info.Result, apiBase, moduleID)
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("module %s did not reach WAITING within %s", moduleID, timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// WaitUntilFinished polls GET /api/info/{moduleID} until its status is
// FINISHED or INTERRUPTED (or timeout elapses), then returns that
// status and its now-meaningful Result.
func WaitUntilFinished(httpClient *http.Client, apiBase, moduleID string, timeout time.Duration) (status, result string, err error) {
	deadline := time.Now().Add(timeout)
	for {
		info, infoErr := FetchModuleInfo(httpClient, apiBase, moduleID)
		if infoErr == nil {
			if info.Status == "FINISHED" || info.Status == "INTERRUPTED" {
				return info.Status, info.Result, nil
			}
			status = info.Status
		}
		if time.Now().After(deadline) {
			return status, "", fmt.Errorf("module %s did not finish within %s", moduleID, timeout)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// PlanDetail is the minimal shape needed from GET /api/plan/{planID} —
// unlike PlanModule (the module list a plan is CREATED with), this
// response's own "modules[].instances" list grows live as a driver
// creates each module instance, letting a poller discover new ones
// without needing to be told about them directly.
type PlanDetail struct {
	Modules []struct {
		Instances []string `json:"instances"`
	} `json:"modules"`
}

// PlanInstances returns every module instance id planID has created so
// far, across all of its module-list entries.
func PlanInstances(httpClient *http.Client, apiBase, planID string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, apiBase+"api/plan/"+planID, nil)
	if err != nil {
		return nil, err
	}
	body, status, err := Do(httpClient, req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get plan: unexpected status %d", status)
	}
	var detail PlanDetail
	if err := json.Unmarshal(body, &detail); err != nil {
		return nil, err
	}
	var ids []string
	for _, m := range detail.Modules {
		ids = append(ids, m.Instances...)
	}
	return ids, nil
}

// LogEntry is the subset of one GET /api/log/{id} entry a poller
// watching for the suite's own browser-automation stuck-points needs —
// see conformance/issuer/scripts/run-fapi2sp-battery/unblock.go's own
// doc comment for what these two fields are used for.
type LogEntry struct {
	Msg            string `json:"msg"`
	ImplicitSubmit *struct {
		FullURL string `json:"fullUrl"`
	} `json:"implicit_submit"`
	Upload string `json:"upload"`
}

// FetchModuleLog returns every log entry GET /api/log/{moduleID} has
// recorded so far.
func FetchModuleLog(httpClient *http.Client, apiBase, moduleID string) ([]LogEntry, error) {
	req, err := http.NewRequest(http.MethodGet, apiBase+"api/log/"+moduleID, nil)
	if err != nil {
		return nil, err
	}
	body, status, err := Do(httpClient, req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get log: unexpected status %d", status)
	}
	var entries []LogEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// PathOf returns fullURL's own path component — the suite's own
// implicit-submit route is always addressed relative to apiBase, not
// as an absolute URL, matching how every other endpoint a driver calls
// is built.
func PathOf(fullURL string) (string, bool) {
	u, err := url.Parse(fullURL)
	if err != nil || u.Path == "" {
		return "", false
	}
	return u.Path, true
}

// Do executes req and returns its body and status code, or an error if
// the request itself failed or the body couldn't be read. req.URL is
// always built by this package's own callers from a developer-supplied
// -suite flag plus fixed API paths (api/plan, api/runner, api/info/...,
// api/log/...) — never from untrusted external input — so this isn't a
// server-side request forgery risk despite gosec's taint analysis
// flagging any *http.Request reaching a Do call as one.
func Do(httpClient *http.Client, req *http.Request) (body []byte, status int, err error) {
	res, err := httpClient.Do(req) //nolint:gosec // see doc comment above: req.URL is always developer-configured, not attacker-controlled
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = res.Body.Close() }()
	body, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("read response body: %w", err)
	}
	return body, res.StatusCode, nil
}
