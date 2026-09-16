from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import json
import secrets

app = Flask(__name__)
CORS(app)

currentNonce = None

@app.route("/generate-nonce", methods=["GET"])
def generate_nonce():
    global currentNonce
    currentNonce = secrets.token_hex(32)
    return jsonify({
        "success": True,
        "nonce": currentNonce
    })

# Load public key database
with open("keys.json") as f:
    PUBLIC_KEYS = json.load(f)

@app.route("/verify-signature", methods=["POST"])
def verify_signature():
    global currentNonce
    try:
        data = request.get_json()
        signature = data.get("signature")
        keyId = data.get("keyId")

        if not signature:
            return jsonify({"success": False, "error": "Missing signature"}), 400
        
        if not keyId:
            return jsonify({"success": False, "error": "Missing key_id"}), 400

        if not currentNonce:
            return jsonify({"success": False, "error": "No active nonce. Generate a new nonce first."}), 400
        
        try:
            message_bytes = bytes.fromhex(currentNonce)
        except Exception as e:
            return jsonify({"success": False, "error": "Invalid nonce format on server", "details": str(e)}), 500

        try:
            signature_bytes = bytes.fromhex(signature)
        except Exception as e:
            return jsonify({"success": False, "error": "Invalid signature hex", "details": str(e)}), 400

        # Lookup correct public key
        pub_pem = PUBLIC_KEYS.get(keyId)
        if not pub_pem:
            return jsonify({"success": False, "error": f"Unknown key_id: {keyId}"})

        try:
            public_key = serialization.load_pem_public_key(pub_pem.encode())
        except Exception as e:
            return jsonify({"success": False, "error": "Failed to load public key PEM", "details": str(e)}), 500

        public_key.verify(
            signature_bytes,
            message_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return jsonify({
            "success": True,
            "message": "Signature verified successfully! Authentication complete."
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Signature verification failed"
        })

if __name__ == "__main__":
    app.run(port=5000, debug=True)
