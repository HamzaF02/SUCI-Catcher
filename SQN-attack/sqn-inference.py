import json
import sys
from pathlib import Path


# Config
JSON_FILE = Path("collected.json")
IND_BITS  = 6   # lower bits reserved for IND index; SEQ probing starts here


# Helpers
def conc_to_int(conc_hex: str) -> int | None:
    try:
        return int(conc_hex, 16)
    except Exception as e:
        print(f"ERROR - invalid CONC* hex '{conc_hex}': {e}")
        return None


def get_delta_for_entry(entry: dict, baseline_conc: int) -> int | None:
    try:
        delta_hex = entry.get("delta_hex")
        if delta_hex is not None:
            return int(delta_hex, 16)


        # If delta not given, it calculates it
        conc_hex = entry.get("conc_star_hex")
        if conc_hex is None:
            return None

        conc_int = conc_to_int(conc_hex)
        if conc_int is None:
            return None

        return baseline_conc ^ conc_int

    except Exception as e:
        print(f"ERROR - failed to get delta for entry j={entry.get('j')}: {e}")
        return None


def infer_sqn_bits(baseline_conc: int, entries: list[dict]) -> dict:
    errors = []
    deltas = []
    bits   = {}   # bit_position -> inferred value

    for entry in sorted(entries, key=lambda x: x["j"]):
        j = entry["j"]
        i = j + IND_BITS   # actual SQN bit position being probed

        if i >= 47:
            errors.append(f"j={j}: bit position {i} is outside SQN")
            continue

        delta = get_delta_for_entry(entry, baseline_conc)
        if delta is None:
            errors.append(f"j={j}: could not get delta")
            continue

        deltas.append((j, i, delta))

        # Get i-th and i+1 th bit to infer pattern
        bit_i  = (delta >> i) & 1
        bit_i1 = (delta >> (i + 1)) & 1

        if bit_i == 1 and bit_i1 == 0:
            inferred = 0
        elif bit_i == 1 and bit_i1 == 1:
            inferred = 1
        else:
            errors.append(
                f"j={j}: unexpected pattern bit[{i}]={bit_i}, bit[{i+1}]={bit_i1} "
                f"(delta=0x{delta:012x})"
            )
            continue
        
        # In the case of repeat from data source
        if i in bits and bits[i] != inferred:
            errors.append(f"j={j}: conflicting inference for bit {i}, keeping first")
            continue
        
        # Add the inferred bit in the i-th position
        bits[i] = inferred

    # Putting the bits into a bit-string
    x = 0
    for pos, bit in bits.items():
        x |= (bit << pos)
    
    sqn = (x - 1) if x > 0 else None
    
    # Extracts the SEQ, ignoring the ID
    seq = x >> IND_BITS

    return {
        "bits":   bits,
        "x":      x,
        "sqn":    sqn,
        "seq":    seq,
        "deltas": deltas,
        "errors": errors,
    }


def get_grouped_entries(records: list[dict]) -> dict[int, list[dict]]:
    # Groups the entries per ran_ue_ngap_id

    grouped = {}

    for entry in records:
        # Get RAN ID per entry
        try:
            ran_ue_id = entry["ran_ue_ngap_id"]
        except Exception:
            print(f"ERROR - malformed entry missing ran_ue_ngap_id: {entry}")
            continue

        
        # Check for existing list, if not create.
        if ran_ue_id not in grouped:
            grouped[ran_ue_id] = []

        # Append ran id to list
        grouped[ran_ue_id].append(entry)

    return grouped


def process_ue(ran_ue_id: int, entries: list[dict]):
    print(f"\n{'+' * 60}")
    print(f"RAN-UE-NGAP-ID: {ran_ue_id}")
    print(f"Total entries: {len(entries)}")

    # Get baseline and probes from collected AUTS
    baselines = [e for e in entries if e.get("j") == -1]
    probes    = sorted([e for e in entries if e.get("j", -2) >= 0], key=lambda e: e["j"])

    if not baselines:
        print("ERROR - no baseline entry found (j=-1)")
        return

    if not probes:
        print("ERROR - no probe entries found (j>=0)")
        return

    # Get the baseline CONC*
    baseline_hex = baselines[0].get("conc_star_hex")
    if baseline_hex is None:
        print("ERROR - baseline entry missing conc_star_hex")
        return

    # Turn CONC* into an integer
    baseline_conc = conc_to_int(baseline_hex)
    if baseline_conc is None:
        print("ERROR - failed to parse baseline CONC*")
        return


    print(f"Baseline CONC*: 0x{baseline_conc:012x}")
    print(f"Probe count: {len(probes)}")
    print(f"j values: {[e['j'] for e in probes]}")

    # Infer SQN bits
    result = infer_sqn_bits(baseline_conc, probes)

    # Print table
    print(f"\n  {'j':>3}  {'bit_pos':>7}  {'delta':>16}  {'pattern':>9}  inferred")
    print(f"  {'-' * 63}")
    
    for j, i, delta in result["deltas"]:
        bit_i  = (delta >> i) & 1
        bit_i1 = (delta >> (i + 1)) & 1
        inferred = result["bits"].get(i, "ERR")

        print(
            f"  j={j:>2}  bit[{i:>2}]  "
            f"delta=0x{delta:012x}  ({bit_i},{bit_i1})     X[{i}]={inferred}"
        )

    # Print final results
    print(f"\nInference results")
    print(f"Bits recovered: {len(result['bits'])}")
    print(f"Bit positions: {sorted(result['bits'].keys())}")

    # Create a printable bitstring
    if result["bits"]:
        lowest = min(result["bits"].keys())
        highest = max(result["bits"].keys())
        bit_string = "".join(str(result["bits"].get(pos, "?")) for pos in range(lowest, highest + 1))
        print(f"Bit string: {bit_string}")
    
    print(f"Inferred SEQ: {result['seq']} (amount of past AKA sessions ~ withing bit range)")

    if result["sqn"] is not None:
        print(f"Inferred SQN_HN_0: {result['sqn']}  (0x{result['sqn']:012x})")
    else:
        print("SQN_HN_0: unable to determine")

    if result["errors"]:
        print(f"\nWarnings")
        for error in result["errors"]:
            print(f"  - {error}")


def main(path: str = str(JSON_FILE)):
    json_path = Path(path)

    if not json_path.exists():
        print(f"ERROR - file not found: {json_path}")
        return

    try:
        collected = json.loads(json_path.read_text())
    except Exception as e:
        print(f"ERROR - failed to read JSON file '{json_path}': {e}")
        return

    if not isinstance(collected, list):
        print(f"ERROR - expected top-level JSON list in '{json_path}'")
        return

    grouped = get_grouped_entries(collected)

    print(f"Loaded {len(collected)} entries from '{json_path}'")
    print(f"Found {len(grouped)} UE(s)")
    print(f"Using IND_BITS={IND_BITS} (SEQ probing starts at bit {IND_BITS})")

    for ran_ue_id in sorted(grouped.keys()):
        process_ue(ran_ue_id, grouped[ran_ue_id])

    print(f"\n{'+' * 60}")
    print("Inference is complete.")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else str(JSON_FILE)
    main(path)