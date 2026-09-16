const pkcs11js = require('pkcs11js');
require('dotenv').config();
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const port = 3000;

// Loading and initializing the PKCS#11 module
const pkcs11 = new pkcs11js.PKCS11();
let selectedSlot = null;
let activeSession = null;
let privkey = null;
let pubkey = null;
let currentNonce = null;
let activeKeyId = null;
let activeKeyLabel = null;

try {
    const token_path = process.env.PATH_TO_TOKEN_LIBRARY;
    pkcs11.load(token_path);
    pkcs11.C_Initialize();
} catch(err) {
    console.error("Error loading and initializing the module:", err);
    process.exit(1);
}

const myServer = http.createServer((req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'OPTIONS,GET,POST');
    res.setHeader('Access-Control-Allow-Headers', 'content-type');

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        res.writeHead(204); //No content error
        res.end();
        return;
    }


    switch (req.url) {
        case "/": {
            if (req.method !== 'GET') {
                res.writeHead(405, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Method not allowed' }));
                return;
            }

            fs.readFile(path.join(__dirname, "public", "index.html"), (err, data) => {
                if (err) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Error loading HTML file' }));
                    console.error("Error loading html file:", err);
                } else {
                    res.writeHead(200, { 'Content-Type': 'text/html' });
                    res.end(data);
                }
            });
            break;
        }

        case "/slots": {
            if (req.method !== 'GET') {
                res.writeHead(405, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Method not allowed' }));
                return;
            }

            try {
                const slots = pkcs11.C_GetSlotList(true);
                
                const slotInfo = slots.map((slotBuffer, index) => {
                    // Convert Buffer to integer (little-endian 32-bit unsigned)
                    const slotId = slotBuffer.readUInt32LE(0);
                    const info = pkcs11.C_GetTokenInfo(slotBuffer);
                    return {
                        index: index,
                        slotNumber: slotId,
                        slotBuffer: slotBuffer, // Keep original buffer for operations
                        label: info.label.trim()
                    };
                });
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ 
                    success: true, 
                    slots: slotInfo.map(s => ({
                        index: s.index,
                        slotNumber: s.slotNumber,
                        label: s.label
                    }))
                }));
            } catch (err) {
                console.error("Error getting slot list:", err);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ 
                    success: false,
                    error: 'Failed to retrieve slots' 
                }));
            }
            break;
        }
             
        case "/login": {
            if (req.method !== 'POST') {
                res.writeHead(405, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Method not allowed' }));
                return;
            }

            let body = '';
            req.on('data', chunk => {
                body += chunk;
            });
            
            req.on('end', () => {
                try {
                    const { chosenSlot, pin } = JSON.parse(body);

                    const slots = pkcs11.C_GetSlotList(true);
                    
                    if (chosenSlot < 0 || chosenSlot >= slots.length) {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Invalid slot index' }));
                        return;
                    }
                    
                    // Close existing session if any
                    if (activeSession !== null) {
                        try {
                            pkcs11.C_Logout(activeSession);
                            pkcs11.C_CloseSession(activeSession);
                        } catch (e) {
                            console.error("Error closing previous session:", e);
                        }
                    }
                    
                    selectedSlot = slots[chosenSlot];
                    console.log("Selected slot: ",selectedSlot);
                    activeSession = pkcs11.C_OpenSession(
                        selectedSlot, 
                        pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION
                    );
                    try {
                        pkcs11.C_Login(activeSession, pkcs11js.CKU_USER, pin);
                    } catch(e) {
                        console.error("Failed to login",e);
                    }
                    
                    
                    // Find private key
                    pkcs11.C_FindObjectsInit(activeSession, [
                        { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY }
                    ]);
                    const foundKeys = pkcs11.C_FindObjects(activeSession);
                    pkcs11.C_FindObjectsFinal(activeSession);

                    //Retrieve label and id
                    const attrs = pkcs11.C_GetAttributeValue(activeSession, foundKeys, [
                        { type: pkcs11js.CKA_LABEL },
                        { type: pkcs11js.CKA_ID }
                    ]);
                    activeKeyLabel = attrs[0].value.toString();
                    activeKeyId = attrs[1].value.toString("hex");
                    
                    if (!foundKeys || foundKeys.length === 0) {
                        pkcs11.C_Logout(activeSession);
                        pkcs11.C_CloseSession(activeSession);
                        activeSession = null;
                        
                        res.writeHead(404, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'No private key found in slot' }));
                        return;
                    }
                    
                    const keyHandle = foundKeys[0];
                    if (typeof keyHandle === "number") {
                    const buf = Buffer.alloc(4);
                    buf.writeUInt32LE(keyHandle, 0);
                    privkey = buf;
                    } else {
                    privkey = keyHandle; //a Buffer
                    }

                    console.log("Private key handle:", privkey);
                    
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: true,
                        message: "Login successful", 
                        slotIndex: chosenSlot 
                    }));

                } catch (e) {
                    console.error("Error during login:", e);
                    
                    // Clean up session on error
                    if (activeSession !== null) {
                        try {
                            pkcs11.C_Logout(activeSession);
                            pkcs11.C_CloseSession(activeSession);
                        } catch (cleanupErr) {
                            console.error("Error during cleanup:", cleanupErr);
                        }
                        activeSession = null;
                    }
                    
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        error: 'Authentication failed',
                        details: e.message 
                    }));
                }
            });
            break;
        }

        case "/logout": {
            if (req.method !== 'POST') {
                res.writeHead(405, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Method not allowed' }));
                return;
            }

            try {
                if (activeSession !== null) {
                    pkcs11.C_Logout(activeSession);
                    pkcs11.C_CloseSession(activeSession);
                    activeSession = null;
                    privkey = null;
                    pubkey = null;
                    selectedSlot = null;
                    currentNonce = null;
                }
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ message: 'Logged out successfully' }));
            } catch (e) {
                console.error("Error during logout:", e);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Logout failed' }));
            }
            break;
        }

        case "/set-nonce": {
            if (req.method != 'POST') {
                res.writeHead(405);
                res.end(JSON.stringify({ error: "Method not allowed" }));
                return;
            }

            let body = "";
            req.on("data", chunk => body += chunk);
            req.on("end", () => {
                const { nonce } = JSON.parse(body);

                currentNonce = nonce;     //store nonce from frontend

                res.writeHead(200, {"Content-Type": "application/json"});
                res.end(JSON.stringify({ success: true }));
            });

            break;
        }

        case "/sign-nonce": {
            if (req.method !== 'POST') {
                res.writeHead(405, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Method not allowed' }));
                return;
            }

            try {
                if (!activeSession || !privkey) {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: false,
                        error: 'Not logged in' 
                    }));
                    return;
                }

                if (!currentNonce) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ 
                        success: false,
                        error: 'No nonce generated' 
                    }));
                    return;
                }

                // Sign the hash
                pkcs11.C_SignInit(activeSession,{mechanism: pkcs11js.CKM_SHA256_RSA_PKCS} ,privkey );
                const signature = pkcs11.C_Sign(activeSession, Buffer.from(currentNonce, "hex"), Buffer.alloc(256));

                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ 
                    success: true,
                    signature: signature.toString('hex'),
                    keyId: activeKeyId,
                    message: 'Nonce signed successfully'
                }));
            } catch (e) {
                console.error("Error signing nonce:", e);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ 
                    success: false,
                    error: e.message 
                }));
            }
            break;
        }

        default: {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Not found' }));
            break;
        }
    }
});

// Graceful shutdown
process.on('SIGINT', () => {
    
    if (activeSession !== null) {
        try {
            pkcs11.C_Logout(activeSession);
            pkcs11.C_CloseSession(activeSession);
            activeSession = null;
            privkey = null;
            pubkey = null;
            currentNonce = null;
        } catch (e) {
            console.error("Error closing session during shutdown:", e);
        }
    }
    
    try {
        pkcs11.C_Finalize();
    } catch (e) {
        console.error("Error finalizing PKCS#11:", e);
    }
    
    process.exit(0);
});




