// This file drives the OpenID Foundation conformance suite's own REST
// API (POST /api/plan, POST /api/runner, GET /api/info/{id}) — generic
// to the suite itself, with no OID4VCI-specific content. Ported
// near-verbatim from FAPIgo's own cmd/conformance-client/suite.go,
// which established this same pattern for FAPI2 client certification
// against the identical suite.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// suitePlan is the minimal shape this driver needs back from POST
// /api/plan — the plan's id, and every module the plan wants run, in
// the order the suite itself lists them.
type suitePlan struct {
	ID      string       `json:"id"`
	Modules []planModule `json:"modules"`
}

// planModule is one entry of a created plan's own module list — the
// suite lists every module/variant crossing the plan enumerates
// (confirmed live: the HAIP wallet plan repeats each of its 4
// module classes across 3 module-list entries — immediate+plain,
// deferred+plain, immediate+encrypted — plus a 4th entry of generic
// FAPI2SP battery modules), so Variant is what actually distinguishes
// one crossing from another when TestModule repeats.
type planModule struct {
	TestModule string            `json:"testModule"`
	Variant    map[string]string `json:"variant"`
}

// suiteModule is the minimal shape this driver needs back from POST
// /api/runner: the module's own id, and the base URL
// (https://.../test/a/<alias>) its discovery document, authorization
// endpoint, etc. all live under.
type suiteModule struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// createPlan creates a new conformance-suite test plan for planName
// (with any [variant=value] selectors already embedded, matching how
// run-test-plan.py's own CLI syntax works), posting configJSON as the
// plan configuration body, and returns the new plan's id and the full
// module list it wants run, in the suite's own order.
func createPlan(httpClient *http.Client, apiBase, planName string, variant map[string]string, configJSON []byte) (string, []planModule, error) {
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

	body, status, err := do(httpClient, req)
	if err != nil {
		return "", nil, err
	}
	if status != http.StatusCreated {
		return "", nil, fmt.Errorf("create plan: unexpected status %d: %s", status, body)
	}
	var plan suitePlan
	if err := json.Unmarshal(body, &plan); err != nil {
		return "", nil, fmt.Errorf("decode plan response: %w", err)
	}
	return plan.ID, plan.Modules, nil
}

// createModuleInstance creates one test module instance within planID
// and returns its id and base URL. variant must repeat the exact
// resolved variant map the plan's own module list entry already fixed
// for testName (planModule.Variant) — confirmed live: POST /api/runner
// does not infer it from plan+test alone when a plan's module list
// enumerates more than one variant crossing for the same testName
// (this plan's own 3 issuance-mode/encryption crossings), rejecting
// the request with "Missing value for required variant parameter" for
// every axis it can't resolve on its own otherwise.
func createModuleInstance(httpClient *http.Client, apiBase, planID, testName string, variant map[string]string) (suiteModule, error) {
	q := url.Values{}
	q.Set("test", testName)
	q.Set("plan", planID)
	if len(variant) > 0 {
		variantJSON, err := json.Marshal(variant)
		if err != nil {
			return suiteModule{}, fmt.Errorf("marshal variant: %w", err)
		}
		q.Set("variant", string(variantJSON))
	}

	req, err := http.NewRequest(http.MethodPost, apiBase+"api/runner?"+q.Encode(), nil)
	if err != nil {
		return suiteModule{}, err
	}

	body, status, err := do(httpClient, req)
	if err != nil {
		return suiteModule{}, err
	}
	if status != http.StatusCreated {
		return suiteModule{}, fmt.Errorf("create module instance: unexpected status %d: %s", status, body)
	}
	var module suiteModule
	if err := json.Unmarshal(body, &module); err != nil {
		return suiteModule{}, fmt.Errorf("decode module response: %w", err)
	}
	return module, nil
}

// waitUntilWaiting polls GET /api/info/{moduleID} until the module
// reaches WAITING, the state in which it's actually ready to receive
// the wallet's first request. A module instance is not immediately
// usable right after creation — the suite still has async setup to do
// (server configuration, JWKS generation) — and firing a request at it
// too early doesn't just fail harmlessly: the module treats the
// unexpected early arrival as if it belonged to a later step, gets
// stuck (INTERRUPTED with "Illegal test state change"), and can never
// recover for the rest of its run (the same failure mode FAPIgo's own
// cmd/conformance-client discovered driving an analogous suite plan).
func waitUntilWaiting(httpClient *http.Client, apiBase, moduleID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		req, err := http.NewRequest(http.MethodGet, apiBase+"api/info/"+moduleID, nil)
		if err != nil {
			return err
		}
		body, status, err := do(httpClient, req)
		if err != nil {
			return err
		}
		if status == http.StatusOK {
			var info moduleInfo
			if err := json.Unmarshal(body, &info); err == nil {
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
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("module %s did not reach WAITING within %s", moduleID, timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// moduleInfo is the minimal shape this driver needs from GET
// /api/info/{id} — the module's current lifecycle status, and its
// graded result once that status is final. Result is meaningless while
// Status isn't yet FINISHED or INTERRUPTED — the suite leaves a stale
// default in that field until then.
type moduleInfo struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

// waitUntilFinished polls GET /api/info/{moduleID} until its status is
// FINISHED or INTERRUPTED (or timeout elapses), then returns that
// status and its now-meaningful Result.
func waitUntilFinished(httpClient *http.Client, apiBase, moduleID string, timeout time.Duration) (status, result string, err error) {
	deadline := time.Now().Add(timeout)
	for {
		req, reqErr := http.NewRequest(http.MethodGet, apiBase+"api/info/"+moduleID, nil)
		if reqErr != nil {
			return "", "", reqErr
		}
		body, httpStatus, doErr := do(httpClient, req)
		if doErr != nil {
			return "", "", doErr
		}
		if httpStatus == http.StatusOK {
			var info moduleInfo
			if err := json.Unmarshal(body, &info); err == nil {
				if info.Status == "FINISHED" || info.Status == "INTERRUPTED" {
					return info.Status, info.Result, nil
				}
				status = info.Status
			}
		}
		if time.Now().After(deadline) {
			return status, "", fmt.Errorf("module %s did not finish within %s", moduleID, timeout)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func do(httpClient *http.Client, req *http.Request) (body []byte, status int, err error) {
	res, err := httpClient.Do(req)
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
