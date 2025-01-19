document.addEventListener("DOMContentLoaded", () => {
    let btn = document.getElementById("button");
    let st = document.getElementById("state");

    let onState = (response) => {
        console.log("popup: onState=" + response.status);
        st.innerText = response.status;
        btn.innerText = response.status === "Connected" ? "Disconnect" : "Connect";
    };

    chrome.runtime.sendMessage({ command: "queryState" }, onState);

    btn.addEventListener("click", () => {
        chrome.runtime.sendMessage({ command: "toggleProxy" }, onState);
    });
})
