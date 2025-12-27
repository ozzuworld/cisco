#!/usr/bin/env python3
"""BE-027: Test dry-run / estimate endpoint"""

import json


def test_estimate_endpoint():
    """
    Demonstrate the estimate endpoint for dry-run previews.
    """
    print("=" * 60)
    print("BE-027: Dry-Run / Estimate Endpoint")
    print("=" * 60)

    print("\n1. REQUEST: Estimate job (same payload as POST /jobs)")
    print("-" * 60)

    request_payload = {
        "publisher_host": "10.10.10.10",
        "port": 22,
        "username": "admin",
        "password": "password123",
        "nodes": ["10.10.10.10", "10.10.10.11"],
        "profile": "core_dumps",
        "options": {
            "time_mode": "range",
            "start_time": "2025-12-27T18:00:00Z",
            "end_time": "2025-12-27T20:00:00Z"
        }
    }

    print("POST /jobs/estimate")
    print(json.dumps(request_payload, indent=2))

    print("\n\n2. RESPONSE: Estimate preview (NO job created)")
    print("-" * 60)

    estimate_response = {
        "profile": "core_dumps",
        "total_nodes": 2,
        "total_commands": 4,  # 2 paths × 2 nodes
        "time_mode": "range",
        "requested_start_time": "2025-12-27T18:00:00Z",
        "requested_end_time": "2025-12-27T20:00:00Z",
        "requested_reltime_minutes": None,
        "computed_reltime_unit": "hours",
        "computed_reltime_value": 3,
        "computation_timestamp": "2025-12-27T21:00:05Z",
        "nodes": [
            {
                "node": "10.10.10.10",
                "total_commands": 2,
                "commands": [
                    {
                        "path": "activelog/platform/log/*",
                        "command": "file get activelog activelog/platform/log/* reltime hours 3 compress",
                        "reltime_unit": "hours",
                        "reltime_value": 3
                    },
                    {
                        "path": "activelog/platform/drf/tar/*",
                        "command": "file get activelog activelog/platform/drf/tar/* reltime hours 3 compress",
                        "reltime_unit": "hours",
                        "reltime_value": 3
                    }
                ]
            },
            {
                "node": "10.10.10.11",
                "total_commands": 2,
                "commands": [
                    {
                        "path": "activelog/platform/log/*",
                        "command": "file get activelog activelog/platform/log/* reltime hours 3 compress",
                        "reltime_unit": "hours",
                        "reltime_value": 3
                    },
                    {
                        "path": "activelog/platform/drf/tar/*",
                        "command": "file get activelog activelog/platform/drf/tar/* reltime hours 3 compress",
                        "reltime_unit": "hours",
                        "reltime_value": 3
                    }
                ]
            }
        ]
    }

    print(json.dumps(estimate_response, indent=2))

    print("\n\n3. WHAT FRONTEND CAN SHOW:")
    print("-" * 60)
    print("✓ This will run 4 commands on 2 nodes")
    print("✓ Time range: 18:00 → 20:00 (computed as reltime hours 3)")
    print("✓ Paths to collect:")
    print("  - activelog/platform/log/*")
    print("  - activelog/platform/drf/tar/*")
    print("✓ Preview of actual CUCM commands:")
    print("  - file get activelog activelog/platform/log/* reltime hours 3 compress")
    print("  - file get activelog activelog/platform/drf/tar/* reltime hours 3 compress")

    print("\n\n4. BENEFITS:")
    print("-" * 60)
    print("✓ Avoid wasted runs - preview before executing")
    print("✓ Verify reltime computation is correct")
    print("✓ Confirm which paths will be collected")
    print("✓ See exact CUCM commands that will run")
    print("✓ No job created, no resources consumed")
    print("✓ Fast response (no SSH connection needed)")

    print("\n\n5. RELATIVE MODE EXAMPLE:")
    print("-" * 60)

    relative_request = {
        "publisher_host": "10.10.10.10",
        "nodes": ["10.10.10.10"],
        "profile": "core_dumps",
        "options": {
            "time_mode": "relative",
            "reltime_minutes": 120
        }
    }

    print("Request:")
    print(json.dumps(relative_request, indent=2))

    relative_response = {
        "profile": "core_dumps",
        "total_nodes": 1,
        "total_commands": 2,
        "time_mode": "relative",
        "requested_reltime_minutes": 120,
        "computed_reltime_unit": "minutes",
        "computed_reltime_value": 120,
        "computation_timestamp": "2025-12-27T21:00:05Z",
        "nodes": [
            {
                "node": "10.10.10.10",
                "total_commands": 2,
                "commands": [
                    {
                        "path": "activelog/platform/log/*",
                        "command": "file get activelog activelog/platform/log/* reltime minutes 120 compress",
                        "reltime_unit": "minutes",
                        "reltime_value": 120
                    },
                    {
                        "path": "activelog/platform/drf/tar/*",
                        "command": "file get activelog activelog/platform/drf/tar/* reltime minutes 120 compress",
                        "reltime_unit": "minutes",
                        "reltime_value": 120
                    }
                ]
            }
        ]
    }

    print("\nResponse:")
    print(json.dumps(relative_response, indent=2))

    print("\n\n" + "=" * 60)
    print("✓ All examples demonstrated successfully!")
    print("=" * 60)


def test_usage_flow():
    """
    Demonstrate typical user flow with estimate endpoint.
    """
    print("\n\n" + "=" * 60)
    print("TYPICAL USER FLOW")
    print("=" * 60)

    print("\nStep 1: User configures job parameters in frontend")
    print("  - Select profile: 'core_dumps'")
    print("  - Select nodes: 10.10.10.10, 10.10.10.11")
    print("  - Set time range: 18:00 → 20:00")

    print("\nStep 2: Frontend calls POST /jobs/estimate")
    print("  ↓ Fast response (no SSH, no job creation)")

    print("\nStep 3: Frontend shows preview:")
    print("  ┌─────────────────────────────────────────────┐")
    print("  │ Job Preview                                 │")
    print("  ├─────────────────────────────────────────────┤")
    print("  │ • Profile: core_dumps                       │")
    print("  │ • Nodes: 2                                  │")
    print("  │ • Commands: 4                               │")
    print("  │ • Time: 18:00 → 20:00 (reltime hours 3)     │")
    print("  │                                             │")
    print("  │ Commands per node:                          │")
    print("  │   - activelog/platform/log/*                │")
    print("  │   - activelog/platform/drf/tar/*            │")
    print("  │                                             │")
    print("  │ [Cancel]  [Run Job] ←                       │")
    print("  └─────────────────────────────────────────────┘")

    print("\nStep 4: User reviews and clicks 'Run Job'")
    print("  ↓ Frontend calls POST /jobs (actual execution)")

    print("\nStep 5: Job executes with confidence")
    print("  ✓ User knows exactly what will happen")
    print("  ✓ No surprises about time range")
    print("  ✓ No wasted runs")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_estimate_endpoint()
    test_usage_flow()
