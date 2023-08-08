export function run() {

const advertiseExitNode = {{ .AdvertiseExitNode }};
const isUnraid = {{ .IsUnraid }};
const unraidCsrfToken = "{{ .UnraidToken }}";
let fetchingUrl = false;
var data = {
AdvertiseRoutes: "{{ .AdvertiseRoutes }}",
AdvertiseExitNode: advertiseExitNode,
Reauthenticate: false,
ForceLogout: false
};

function postData(e) {
e.preventDefault();

if (fetchingUrl) {
    return;
}

fetchingUrl = true;
const urlParams = new URLSearchParams(window.location.search);
const token = urlParams.get("SynoToken");
const nextParams = new URLSearchParams({ up: true });
if (token) {
    nextParams.set("SynoToken", token)
}
const nextUrl = new URL(window.location);
nextUrl.search = nextParams.toString()

let body = JSON.stringify(data);
let contentType = "application/json";

if (isUnraid) {
    const params = new URLSearchParams();
    params.append("csrf_token", unraidCsrfToken);
    params.append("ts_data", JSON.stringify(data));

    body = params.toString();
    contentType = "application/x-www-form-urlencoded;charset=UTF-8";
}

const url = nextUrl.toString();
fetch(url, {
    method: "POST",
    headers: {
        "Accept": "application/json",
        "Content-Type": contentType,
    },
    body: body
}).then(res => res.json()).then(res => {
    fetchingUrl = false;
    const err = res["error"];
    if (err) {
        throw new Error(err);
    }
    const url = res["url"];
    if (url) {
        if(isUnraid) {
            window.open(url, "_blank");
        } else {
            document.location.href = url;
        }
    } else {
        location.reload();
    }
}).catch(err => {
    alert("Failed operation: " + err.message);
});
}

document.querySelectorAll(".js-loginButton").forEach(function (el){
el.addEventListener("click", function(e) {
    data.Reauthenticate = true;
    postData(e);
});
})
document.querySelectorAll(".js-logoutButton").forEach(function(el) {
el.addEventListener("click", function (e) {
    data.ForceLogout = true;
    postData(e);
});
})
document.querySelectorAll(".js-advertiseExitNode").forEach(function (el) {
el.addEventListener("click", function(e) {
    data.AdvertiseExitNode = !advertiseExitNode;
    postData(e);
});
})
}