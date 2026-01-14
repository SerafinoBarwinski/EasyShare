console.log("Hello dear Programmer")

document.getElementById("login_form").addEventListener("submit", (e) => {
    e.preventDefault();

    const unameIn = document.getElementById("login_input_uname");
    const pswIn = document.getElementById("login_input_psw");

    fetch("/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            username: unameIn.value,
            psw: pswIn.value
        })
    })
        .then(response => {
            if (!response.ok) {
                throw new Error("Request fehlgeschlagen");
            }
            loadContent()
            return response.json();
        })
        .then(data => {
            console.log(data);
        })
        .catch(err => {
            console.error(err);
        });
});

async function loadContent() {
    const res = await fetch("/content", { credentials: "include", method: "GET" });
    const data = await res.json();

    const container = document.getElementById("content");
    data.forEach(element => {
        const subContainer = document.createElement("div");
        subContainer.id = element.id;
        subContainer.onclick = function () {
            window.location.href = `/share/${element.id}`;
        };

        const subConTitle = document.createElement("p");
        subConTitle.innerText = element.path;
        
        const subConMoreIcon = document.createElement("i");
        subConMoreIcon.classList = "fa-solid fa-ellipsis-vertical";
        subConMoreIcon.style = "cursor: pointer; right: 100% !important;"
        subConMoreIcon.onclick = displayMoreMenu(element.id);

        container.appendChild(subContainer);
        subContainer.appendChild(subConTitle);
        subConTitle.appendChild(subConMoreIcon);
    });
}

function displayMoreMenu(id) {
    if (!id) {return}
    
}