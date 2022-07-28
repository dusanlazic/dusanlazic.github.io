function convertDates() {
    Array.from(document.getElementsByClassName("display-date")).forEach(
        element => element.innerHTML = moment(element.dataset.date, 'yyyy-MM-DD HH:mm:ss Z').local().format('LL')
    );
}

convertDates();