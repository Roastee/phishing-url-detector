#!/usr/bin/env python
"""Examine metrics.json structure."""
import json

with open('reports/metrics.json') as f:
    m = json.load(f)

print("=== Top-level keys ===")
for k in m.keys():
    print(f"  {k}")

print("\n=== in_distribution_test ===")
for model, metrics in m.get('in_distribution_test', {}).items():
    print(f"  {model}:")
    for k, v in metrics.items():
        if k != 'confusion_matrix':
            print(f"    {k}: {v}")

print("\n=== independent_test ===")
for ratio, metrics in m.get('independent_test', {}).items():
    if isinstance(metrics, dict):
        print(f"  {ratio}:")
        for k, v in metrics.items():
            if k != 'confusion_matrix':
                print(f"    {k}: {v}")

print("\n=== recall_free_hosting_bootstrap_95ci ===")
print(json.dumps(m.get('recall_free_hosting_bootstrap_95ci', {}), indent=2))

print("\n=== recall_non_free_hosting_bootstrap_95ci ===")
print(json.dumps(m.get('recall_non_free_hosting_bootstrap_95ci', {}), indent=2))

print("\n=== deployment_info ===")
print(json.dumps(m.get('deployment_info', {}), indent=2))