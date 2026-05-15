(function () {
    var lastSeen = localStorage.getItem("lastSeen");
    if (!lastSeen) {
        document.body.classList.add("animate");
        window.addEventListener("load", function () {
            setTimeout(function () {
                document.body.classList.add("animating");
                localStorage.setItem("lastSeen", Date.now());
            }, 100);
        });
    }
})();
