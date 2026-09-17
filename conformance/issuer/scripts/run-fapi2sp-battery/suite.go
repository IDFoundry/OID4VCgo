// This file drives the OpenID Foundation conformance suite's own REST
// API (POST /api/plan, POST /api/runner, GET /api/info/{id}) — generic
// to the suite itself, with no OID4VCI-specific content. Ported
// near-verbatim from cmd/conformance-wallet/suite.go (itself ported
// from FAPIgo's own cmd/conformance-client/suite.go), minus
// waitUntilWaiting: unlike those two binaries, this one never sends
// the module instance its first request itself — the suite's own
// browser automation drives the whole flow — so there's nothing to
// gate on WAITING for.
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

// planModule is one entry of a created plan's own module list —
// Variant is the exact resolved variant map createModuleInstance must
// repeat for that testName.
type planModule struct {
	TestModule string            `json:"testModule"`
	Variant    map[string]string `json:"variant"`
}

// suiteModule is the minimal shape this driver needs back from POST
// /api/runner: the module's own id and base URL.
type suiteModule struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// createPlan creates a new conformance-suite test plan for planName,
// posting configJSON as the plan configuration body, and returns the
// new plan's id and the full module list it wants run.
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
// for testName (planModule.Variant).
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

// moduleInfo is the minimal shape this driver needs from GET
// /api/info/{id} — the module's current lifecycle status, and its
// graded result once that status is final.
type moduleInfo struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

// waitUntilFinished polls GET /api/info/{moduleID} until its status is
// FINISHED or INTERRUPTED (or timeout elapses), then returns that
// status and its now-meaningful Result. The suite's own browser
// automation drives the entire flow behind this call — this binary
// never sends the module instance any request of its own.
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

// planDetail is the minimal shape unblockImplicitCallbacks needs from
// GET /api/plan/{planID} — unlike planModule, this response's own
// "modules[].instances" list grows live as this binary creates each
// module instance, letting the poller discover new ones without
// needing to be told about them directly.
type planDetail struct {
	Modules []struct {
		Instances []string `json:"instances"`
	} `json:"modules"`
}

func planInstances(httpClient *http.Client, apiBase, planID string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, apiBase+"api/plan/"+planID, nil)
	if err != nil {
		return nil, err
	}
	body, status, err := do(httpClient, req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get plan: unexpected status %d", status)
	}
	var detail planDetail
	if err := json.Unmarshal(body, &detail); err != nil {
		return nil, err
	}
	var ids []string
	for _, m := range detail.Modules {
		ids = append(ids, m.Instances...)
	}
	return ids, nil
}

func fetchModuleInfo(httpClient *http.Client, apiBase, moduleID string) (moduleInfo, error) {
	req, err := http.NewRequest(http.MethodGet, apiBase+"api/info/"+moduleID, nil)
	if err != nil {
		return moduleInfo{}, err
	}
	body, status, err := do(httpClient, req)
	if err != nil {
		return moduleInfo{}, err
	}
	if status != http.StatusOK {
		return moduleInfo{}, fmt.Errorf("get info: unexpected status %d", status)
	}
	var info moduleInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return moduleInfo{}, err
	}
	return info, nil
}

// logEntry is the subset of one GET /api/log/{id} entry
// unblockImplicitCallbacks needs — the same "Created random implicit
// submission URL"/"upload placeholder" entries
// unblock-implicit-callback.py's own identical poller reads (see
// unblock.go's own doc comment).
type logEntry struct {
	Msg            string `json:"msg"`
	ImplicitSubmit *struct {
		FullURL string `json:"fullUrl"`
	} `json:"implicit_submit"`
	Upload string `json:"upload"`
}

func fetchModuleLogRaw(httpClient *http.Client, apiBase, moduleID string) ([]logEntry, error) {
	req, err := http.NewRequest(http.MethodGet, apiBase+"api/log/"+moduleID, nil)
	if err != nil {
		return nil, err
	}
	body, status, err := do(httpClient, req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get log: unexpected status %d", status)
	}
	var entries []logEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// pathOf returns fullURL's own path component — the suite's own
// implicit-submit route is always addressed relative to apiBase, not
// as an absolute URL, matching how every other endpoint this binary
// calls is built.
func pathOf(fullURL string) (string, bool) {
	u, err := url.Parse(fullURL)
	if err != nil || u.Path == "" {
		return "", false
	}
	return u.Path, true
}
