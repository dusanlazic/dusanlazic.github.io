var iconDict = {
    "HackTheBox": "simple-icons:hackthebox",
    "Writeup": "ic:baseline-assignment",
    "Passwords": "ic:baseline-vpn-key",
    "Blog": "ic:baseline-chat-bubble",
    "CTF": "ic:baseline-flag",
    "Cryptography": "ic:baseline-vpn-key",
    "Jekyll": "simple-icons:jekyll",
    "SCC 2022": "ic:baseline-flag"
}

function setIcons() {
    Array.from(document.querySelectorAll("[data-collection-name]")).forEach(
        element => element.innerHTML = "<span class=\"iconify-inline mr-2\" data-icon=\"" + iconDict[element.dataset.collectionName] + "\"></span>" + element.innerHTML
    );
}

setIcons();