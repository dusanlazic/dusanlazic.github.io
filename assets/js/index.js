var i = 0;
var text = 'whoami';
var delay = 100;

function addLetter() {
    if (i < text.length) {
        document.getElementById("command").innerHTML += text.charAt(i);
        i++;
        setTimeout(addLetter, delay);
    } else {
        setTimeout(function () {
            document.getElementById("command").remove();
            document.getElementById("cursor").remove();
        }, 1000);

        setTimeout(function () {
            document.getElementById("whoami-content").classList.toggle("is-hidden");
        }, 1100);
    }
}

document.getElementById("cursor").classList.toggle("is-hidden");
document.getElementById("whoami-content").classList.toggle("is-hidden");
setTimeout(addLetter, 1000);