var iconDict = {
    "HackTheBox": "simple-icons:hackthebox",
    "Writeup": "ic:baseline-assignment",
    "Passwords": "ic:baseline-vpn-key",
    "Blog": "ic:baseline-chat-bubble",
    "CTF": "ic:baseline-flag",
    "Cryptography": "ic:baseline-vpn-key",
    "Jekyll": "simple-icons:jekyll",
    "Serbian Cybersecurity Challenge": "ic:baseline-flag",
    "ECSC": "game-icons:european-flag",
    "A/D": "ic:baseline-flag",
}

function setIcons() {
    Array.from(document.querySelectorAll("[data-collection-name]")).forEach(
        element => element.innerHTML = "<span class=\"iconify-inline mr-2\" data-icon=\"" + iconDict[element.dataset.collectionName] + "\"></span>" + element.innerHTML
    );
}

setIcons();