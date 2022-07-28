function clearSelection() {
    let tags = document.getElementsByClassName("tag");
    for (let i = 0; i < tags.length; i++) {
        tags[i].classList.remove('active');
    }

    let tabs = document.getElementsByClassName("tab");
    for (let i = 0; i < tabs.length; i++) {
        tabs[i].classList.remove('active');
    }
}

function setSelection() {
    if (window.location.hash) {
        let slug = decodeURI(window.location.hash.substring(1));

        document.getElementById("tab-all").classList.remove('active');
        document.getElementById("clear-categories").classList.remove('is-hidden');
        document.getElementById("clear-tags").classList.remove('is-hidden');
        document.getElementById("tab-" + slug).classList.add('active');
        document.getElementById("collection-" + slug).classList.add('active');
    } else {
        document.getElementById("tab-all").classList.add('active');
        document.getElementById("clear-categories").classList.add('is-hidden');
        document.getElementById("clear-tags").classList.add('is-hidden');
    }
}

function categoryChanged() {
    clearSelection();
    slug = decodeURI(location.hash.substring(1));

    if (slug === "") {
        document.getElementById("tab-all").classList.add('active');
        document.getElementById("clear-categories").classList.add('is-hidden');
        document.getElementById("clear-tags").classList.add('is-hidden');
    } else {
        document.getElementById("tab-" + slug).classList.add('active');
        document.getElementById("collection-" + slug).classList.add('active');
        document.getElementById("clear-categories").classList.remove('is-hidden');
        document.getElementById("clear-tags").classList.remove('is-hidden');
    }
}

function clearLines() {
    Array.from(document.getElementsByClassName("line")).forEach(
        element => element.remove()
    );
}

window.onhashchange = categoryChanged;
clearLines();
clearSelection();
setSelection();