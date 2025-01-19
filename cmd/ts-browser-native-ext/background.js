// Flag to track proxy status
let proxyEnabled = false;


// Function to change the popup icon
function setPopupIcon(active) {
    const iconPath = active ? "online.png" : "offline.png";

    chrome.action.setIcon({ path: iconPath }, () => {
        if (chrome.runtime.lastError) {
            console.error("Error setting icon to " + active + ":", chrome.runtime.lastError.message);
        }
    });
}

// Function to enable the proxy
function enableProxy() {
    if (disconnected) {
        console.error("Cannot enable proxy, disconnected from native host");
        return;
    }

    // Send message to port
    if (lastProxyPort) {
        nmPort.postMessage({ cmd: "get-status" });        
    } else {
        nmPort.postMessage({ cmd: "up" });
    }
}

// Function to disable the proxy
function disableProxy() {
    setProxy(0);
    
    if (disconnected) {
        console.error("Cannot disable proxy, disconnected from native host");
        return;
    }

    // Send message to port
    //nmPort.postMessage({ cmd: "down" });
}

console.log("starting ts-browser-ext");

console.log("Connecting to native messaging host...");
let nmPort = chrome.runtime.connectNative("com.tailscale.browserext.chrome");
let disconnected = false;
let portError = ""; // error.message if/when nmPort disconnected

nmPort.onDisconnect.addListener(() => {
    disconnected = true;
    const error = chrome.runtime.lastError;
    if (error) {
        console.error("Connection failed:", error.message);
        portError = error.message;
    } else {
        console.error("Disconnected from native host");
    }
});
nmPort.onMessage.addListener((message) => {
    console.log("message from backend: ", message);

    let st = message.status;
    if (st && st.running && st.proxyPort && proxyEnabled) {
        setProxy(st.proxyPort);
    }
})

var lastProxyPort = 0;

function setProxy(proxyPort) {
    if (proxyPort) {
        lastProxyPort = proxyPort;
        console.log("Enabling proxy at port: " + proxyPort);
    } else {
        console.log("Disabling proxy...");
        chrome.proxy.settings.set(
            {
                value: {
                    mode: "direct"
                },
                scope: "regular"
            },
            () => {
                console.log("Proxy disabled.");
            }
        );    
        return;
    }
    chrome.proxy.settings.set(
        {
            value: {
                mode: "fixed_servers",
                rules: {
                    singleProxy: {
                        scheme: "http",
                        host: "127.0.0.1",
                        port: proxyPort
                    },
                    bypassList: ["<local>"]
                }
            },
            scope: "regular"
        },
        () => {
            console.log("Proxy enabled: 127.0.0.1:" + proxyPort);
        }
    );
}

chrome.storage.local.get("profileId", (result) => {
    if (!result.profileId) {
        const profileId = crypto.randomUUID();
        chrome.storage.local.set({ profileId }, () => {
            console.log("Generated profile ID:", profileId);
            nmPort.postMessage({ cmd: "init", initID: profileId });
        });
    } else {
        console.log("Profile ID already exists:", result.profileId);
        nmPort.postMessage({ cmd: "init", initID: result.profileId });
    }
});


// Listener for messages from the popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.command === "queryState") {
        if (disconnected) {
            sendResponse({ status: "Error", error: portError });
            return;
        }
        console.log("bg: queryState, proxy=" + proxyEnabled);
        sendResponse({ status: proxyEnabled ? "Connected" : "Disconnected" });
        return
    } 

    if (message.command === "toggleProxy") {
        console.log("bg: toggleProxy, proxy=" + proxyEnabled);
        proxyEnabled = !proxyEnabled;
        if (proxyEnabled) {
            enableProxy();
            console.log("bg: toggleProxy on, now proxy=" + proxyEnabled);
            sendResponse({ status: "Connected" });
            console.log("bg: toggleProxy on, sent proxy=" + proxyEnabled);
        } else {
            disableProxy();
            console.log("bg: toggleProxy off, now proxy=" + proxyEnabled);
            sendResponse({ status: "Disconnected" });
            console.log("bg: toggleProxy off, sent proxy=" + proxyEnabled);
        }
        setPopupIcon(proxyEnabled);
    }
});
