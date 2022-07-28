var buttonScroll = document.getElementById("scrollTop");

function addCopyButtons() {
    if (navigator.clipboard) {
        let blocks = document.querySelectorAll("pre");
        blocks.forEach((block) => {
            let button = document.createElement("button");

            button.classList = "button is-small is-outlined is-primary";
            button.innerHTML = "Copy&nbsp;&nbsp;<span class=\"iconify is-size-6\" data-icon=\"ic:baseline-content-copy\">"

            button.addEventListener("click", copyCode);
            block.appendChild(button);
        });
    }
}

function copyCode(event) {
    const button = event.srcElement;
    const pre = button.parentElement;
    let code = pre.querySelector("code");
    navigator.clipboard.writeText(code.innerText);

    button.classList = "button is-small is-outlined is-success";
    button.innerHTML = "Copied!&nbsp;&nbsp;<span class=\"iconify is-size-6\" data-icon=\"ic:baseline-check\">"

    setTimeout(() => {
        button.classList = "button is-small is-outlined is-primary";
        button.innerHTML = "Copy&nbsp;&nbsp;<span class=\"iconify is-size-6\" data-icon=\"ic:baseline-content-copy\">"
    }, 2000)
}

function trackScroll() {
    var scrolled = window.pageYOffset;

    if (scrolled > 300) {
        buttonScroll.classList.remove('is-hidden');
    } else {
        buttonScroll.classList.add('is-hidden');
    }
}

window.addEventListener('scroll', trackScroll);
addCopyButtons();