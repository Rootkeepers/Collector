import json

import requests

from bundle_parser import BundleParseError, extract_predicate_from_dsse


ATTESTATIONS_URL = "https://registry.npmjs.org/-/npm/v1/attestations/vite@5.2.0"


def fetch_and_test() -> None:
    """Fetch npm attestations for vite@5.2.0 and locate SLSA provenance."""
    try:
        response = requests.get(ATTESTATIONS_URL, timeout=15)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as error:
        print(f"[-] Failed to fetch npm attestations: {error}")
        return
    except json.JSONDecodeError as error:
        print(f"[-] npm response was not valid JSON: {error}")
        return

    attestations = data.get("attestations")
    if not isinstance(attestations, list):
        print("[-] Could not find a valid 'attestations' array in the npm response.")
        return

    print(f"[*] Found {len(attestations)} attestation(s).")

    for index, attestation in enumerate(attestations, start=1):
        if not isinstance(attestation, dict):
            print(f"[-] Skipping attestation #{index}: item is not an object.")
            continue

        bundle = attestation.get("bundle")
        if not isinstance(bundle, dict):
            print(f"[-] Skipping attestation #{index}: missing or invalid bundle.")
            continue

        try:
            predicate = extract_predicate_from_dsse(bundle)
        except BundleParseError as error:
            print(f"[-] Failed to parse attestation #{index}: {error}")
            continue

        if "buildDefinition" in predicate:
            print("✨ Found the real SLSA provenance!")
            formatted = json.dumps(predicate, indent=2, ensure_ascii=False)
            print(formatted[:800])
            return

        print(f"[*] Attestation #{index} is just a publish receipt.")

    print("[-] No SLSA provenance attestation was found.")


if __name__ == "__main__":
    fetch_and_test()
