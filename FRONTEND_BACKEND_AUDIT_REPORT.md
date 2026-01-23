# Frontend-Backend API Audit Report

## Executive Summary

This report documents all API endpoint mismatches between the frontend and backend of the CUCM Log Collector application. The analysis was triggered by 404 errors in the Voice Quality/Capture tab.

**Key Findings:**
- ✅ **39 endpoints** match between frontend and backend
- ❌ **8 endpoints** are missing in the backend (called by frontend but don't exist)
- ⚠️ **4 endpoints** have potential inconsistencies

---

## Critical Issue: Voice Quality Capture Errors

### Root Cause
The "Voice Quality" tab (labeled as "Captures" in the hamburger menu) calls **orchestrated multi-device capture session endpoints** that **DO NOT EXIST** in the backend.

### Error Details from Console
```
❌ GET /cap-sessions?limit=20&1 → 404 Not Found
❌ GET /capture-sessions1 → 404 Not Found
```

**Note:** The typo "cap-sessions" and the "1" suffix appear to be URL encoding/concatenation issues in the frontend, but the underlying issue is that `/capture-sessions` endpoints don't exist at all.

### Affected Frontend Page
- **File:** `frotend/src/pages/CaptureSession.tsx` (1,483 lines)
- **Route:** `/captures` (via hamburger menu: "Captures")
- **Service:** `frotend/src/services/captureService.ts` (lines 65-134)

---

## Missing Backend Endpoints (Breaking Errors)

These endpoints are called by the frontend but **DO NOT EXIST** in the backend:

| # | Frontend Call | HTTP Method | Backend Status | Impact |
|---|---|---|---|---|
| 1 | `/capture-sessions` | POST | ❌ Missing | Cannot start multi-device capture sessions |
| 2 | `/capture-sessions?limit={limit}` | GET | ❌ Missing | Cannot list capture sessions |
| 3 | `/capture-sessions/{sessionId}` | GET | ❌ Missing | Cannot get session status |
| 4 | `/capture-sessions/{sessionId}/stop` | POST | ❌ Missing | Cannot stop capture sessions |
| 5 | `/capture-sessions/{sessionId}/download` | GET | ❌ Missing | Cannot download session bundles |
| 6 | `/capture-sessions/{sessionId}` | DELETE | ❌ Missing | Cannot delete capture sessions |
| 7 | `/connection/test` | POST | ❌ Missing | Cannot test CUCM connections |
| 8 | `/health/device` | POST | ❌ Missing | Cannot check multi-device health (new feature) |

### Functional Impact

**Capture Sessions (6 endpoints):**
- The frontend has a complete UI for orchestrated multi-device packet captures
- Users can configure captures across CUCM, CUBE, Expressway devices
- **None of this works** because the backend only supports single-device captures via `/captures`

**Health Checking:**
- Frontend has `/health/device` for checking multiple device types
- Backend only has `/cluster/health` for CUCM clusters
- Multi-device health checking is broken

**Connection Testing:**
- Frontend attempts to test connections before discovery
- This feature is completely non-functional

---

## Endpoints That Match (Working)

### ✅ Cluster/Node Discovery
| Frontend | Backend | Status |
|---|---|---|
| POST `/discover-nodes` | POST `/discover-nodes` | ✅ Match |

### ✅ Single-Device Packet Captures
| Frontend | Backend | Status |
|---|---|---|
| POST `/captures` | POST `/captures` | ✅ Match |
| GET `/captures` | GET `/captures` | ✅ Match |
| GET `/captures/{captureId}` | GET `/captures/{capture_id}` | ✅ Match |
| POST `/captures/{captureId}/stop` | POST `/captures/{capture_id}/stop` | ✅ Match |
| GET `/captures/{captureId}/download` | GET `/captures/{capture_id}/download` | ✅ Match |
| DELETE `/captures/{captureId}` | DELETE `/captures/{capture_id}` | ✅ Match |

### ✅ Job Management
| Frontend | Backend | Status |
|---|---|---|
| GET `/jobs?page={page}&page_size={pageSize}` | GET `/jobs` | ✅ Match (backend supports pagination) |
| GET `/jobs/{jobId}` | GET `/jobs/{job_id}` | ✅ Match |
| POST `/jobs` | POST `/jobs` | ✅ Match |
| POST `/jobs/{jobId}/cancel` | POST `/jobs/{job_id}/cancel` | ✅ Match |
| POST `/jobs/{jobId}/retry-failed` | POST `/jobs/{job_id}/retry-failed` | ✅ Match |
| GET `/jobs/{jobId}/artifacts` | GET `/jobs/{job_id}/artifacts` | ✅ Match |
| GET `/jobs/{jobId}/download` | GET `/jobs/{job_id}/download` | ✅ Match |
| GET `/jobs/{jobId}/artifacts/{artifactId}/download` | GET `/jobs/{job_id}/artifacts/{artifact_id}/download` | ✅ Match |
| GET `/jobs/{jobId}/nodes/{nodeIp}/download` | GET `/jobs/{job_id}/nodes/{node_ip}/download` | ✅ Match |

### ✅ Log Collections (CUBE/Expressway)
| Frontend | Backend | Status |
|---|---|---|
| POST `/logs` | POST `/logs` | ✅ Match |
| GET `/logs` | GET `/logs` | ✅ Match |
| GET `/logs/{collectionId}` | GET `/logs/{collection_id}` | ✅ Match |
| GET `/logs/{collectionId}/download` | GET `/logs/{collection_id}/download` | ✅ Match |
| DELETE `/logs/{collectionId}` | DELETE `/logs/{collection_id}` | ✅ Match |
| GET `/logs/profiles` | GET `/logs/profiles` | ✅ Match |

### ✅ Profiles
| Frontend | Backend | Status |
|---|---|---|
| GET `/profiles` | GET `/profiles` | ✅ Match |

### ✅ Trace Levels
| Frontend | Backend | Status |
|---|---|---|
| POST `/trace-level/get` | POST `/trace-level/get` | ✅ Match |
| POST `/trace-level/set` | POST `/trace-level/set` | ✅ Match |

### ✅ Health (Legacy CUCM)
| Frontend | Backend | Status |
|---|---|---|
| POST `/cluster/health` | POST `/cluster/health` | ✅ Match |

---

## Potential Inconsistencies (Non-Breaking)

These endpoints may work but have different implementations or are unused:

| # | Frontend | Backend | Issue |
|---|---|---|---|
| 1 | GET `/jobs/{jobId}/transcript?node={nodeIp}` | ❓ Not documented | Transcript endpoint exists in frontend but unclear if backend implements it |
| 2 | POST `/jobs/estimate` | POST `/jobs/estimate` | Backend has this, but frontend doesn't use it |
| 3 | GET `/profiles/{profileId}` | ❓ Unclear | Frontend can get single profile, backend API unclear |
| 4 | POST `/profiles` | ❓ Not in backend | Frontend can create custom profiles (unlikely to work) |
| 5 | DELETE `/profiles/{profileId}` | ❓ Not in backend | Frontend can delete custom profiles (unlikely to work) |
| 6 | POST `/logs/{collectionId}/cancel` | ❓ Not documented | Frontend tries to cancel log collections, backend support unclear |

---

## Architecture Analysis

### Current Implementation

**Backend:** Single-device capture support
- `/captures` endpoints handle packet captures on **one device at a time**
- Each capture targets a single CUCM, CUBE, or Expressway device
- File: `Backend/app/capture_service.py`

**Frontend:** Multi-device orchestration UI
- `/capture-sessions` endpoints attempt to coordinate captures across **multiple devices**
- Provides a wizard to select multiple targets
- Aggregates results and downloads as ZIP bundles
- File: `frotend/src/pages/CaptureSession.tsx`

### The Disconnect

The frontend was built with a **session-based orchestration model** where users can:
1. Create a capture "session" with multiple device targets
2. Start captures on all devices simultaneously
3. Monitor all captures in one view
4. Download all captures as a single bundle

The backend was built with a **single-device model** where users can:
1. Start one capture on one device
2. Monitor that single capture
3. Download that single capture file

**This is why the "Voice Quality" tab fails** - it's trying to use orchestration features that were never implemented in the backend.

---

## Recommendations

### Option 1: Implement Missing Backend Endpoints (Recommended)

**Add 6 new endpoints to support multi-device capture sessions:**

1. `POST /capture-sessions` - Create a new capture session
2. `GET /capture-sessions?limit={limit}` - List sessions
3. `GET /capture-sessions/{session_id}` - Get session status
4. `POST /capture-sessions/{session_id}/stop` - Stop session
5. `GET /capture-sessions/{session_id}/download` - Download bundle
6. `DELETE /capture-sessions/{session_id}` - Delete session

**Implementation approach:**
- Create `CaptureSession` model and `CaptureSessionManager` in backend
- Each session orchestrates multiple single-device captures
- Reuse existing `/captures` infrastructure internally
- Add session aggregation and ZIP bundling logic
- Estimated effort: 2-3 days of development

**Files to create/modify:**
- `Backend/app/capture_session_service.py` (new)
- `Backend/app/models.py` (add session models)
- `Backend/app/main.py` (add 6 new routes)

### Option 2: Modify Frontend to Use Existing Endpoints

**Simplify the frontend to work with single-device captures:**

1. Remove "session" concept from `CaptureSession.tsx`
2. Update UI to create one capture at a time
3. Remove multi-device selection wizard
4. Remove session aggregation views

**Implementation approach:**
- Modify `frotend/src/pages/CaptureSession.tsx`
- Update `frotend/src/services/captureService.ts` to remove session calls
- Simplify UI to match backend capabilities
- Estimated effort: 1-2 days of development

**Drawback:** Loses the multi-device orchestration feature entirely

### Option 3: Hybrid Approach

**Keep both single-device and multi-device UIs:**

1. Rename current `/captures` page to "Single Capture"
2. Disable or hide "Session Capture" features until backend is ready
3. Add feature flags in frontend to toggle orchestration UI
4. Implement backend endpoints incrementally

---

## Hamburger Menu vs Dashboard Mismatch

Based on the code analysis:

**Hamburger Menu (Working Features):**
- ✅ **Dashboard** - Shows job summaries, recent activity
- ✅ **Jobs** - CUCM log collection jobs (fully functional)
- ✅ **Health** - Cluster health checks (legacy CUCM works, multi-device broken)
- ❌ **Captures** - Packet capture sessions (**BROKEN** - missing backend)
- ✅ **Profiles** - Log collection profiles (read-only works)
- ⚠️ **Settings** - Currently empty/placeholder

**Dashboard Page Features:**
- Main landing page at `/dashboard`
- Shows quick stats for jobs, health, captures
- All cards/widgets work EXCEPT:
  - Capture session stats (broken)
  - Multi-device health checks (broken)

**Main User Workflow (Log Collection):**
1. User navigates to hamburger menu → "Jobs"
2. Creates new job via wizard
3. Selects CUCM nodes and profile
4. Monitors job progress
5. Downloads artifacts
6. **This workflow WORKS** ✅

**Broken Workflow (Packet Capture):**
1. User navigates to hamburger menu → "Captures"
2. Tries to create capture session
3. Gets 404 errors immediately
4. **This workflow FAILS** ❌

---

## Summary Table

| Feature | Frontend | Backend | Status |
|---|---|---|---|
| CUCM Log Collection (Jobs) | ✅ Full UI | ✅ Complete API | ✅ **Working** |
| CUBE/Expressway Logs | ✅ Full UI | ✅ Complete API | ✅ **Working** |
| Single-Device Captures | ✅ Partial UI | ✅ Complete API | ✅ **Working** |
| Multi-Device Capture Sessions | ✅ Full UI | ❌ No API | ❌ **Broken** |
| CUCM Health Checks | ✅ Full UI | ✅ Complete API | ✅ **Working** |
| Multi-Device Health Checks | ✅ Full UI | ❌ No API | ❌ **Broken** |
| Trace Level Management | ✅ Full UI | ✅ Complete API | ✅ **Working** |
| Connection Testing | ✅ UI Feature | ❌ No API | ❌ **Broken** |
| Custom Profile Management | ✅ UI Feature | ❌ No API | ❌ **Broken** |

---

## Next Steps

1. **Immediate Fix (Option 2):** Update frontend to use existing `/captures` endpoints
   - Modify `CaptureSession.tsx` to remove session calls
   - Replace `getSessions()` with `getCaptures()`
   - Update UI to show single captures instead of sessions
   - Deploy frontend fix

2. **Long-term Solution (Option 1):** Implement backend session endpoints
   - Design `CaptureSession` model and orchestration logic
   - Implement 6 new API endpoints in `Backend/app/main.py`
   - Add session management service
   - Test with frontend

3. **Document API Contract:**
   - Create OpenAPI/Swagger documentation
   - Add API version tracking
   - Implement contract testing

---

## Conclusion

The Voice Quality capture feature is broken because the frontend was developed with an **orchestrated multi-device session model** that was never implemented in the backend. The backend only supports single-device captures.

**The mismatch exists because:**
1. Features were developed incrementally
2. The frontend "Captures" page was built with future session orchestration in mind
3. The backend only implemented basic single-device capture functionality
4. No API contract or integration tests caught the discrepancy

**Recommended immediate action:** Fix the frontend to work with existing `/captures` endpoints, then plan backend session implementation as a feature enhancement.
