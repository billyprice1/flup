(function() {
	var animeGrill = document.getElementById("anime");
	var animeEngineTimer = null;

	animeGrill.onclick = function() {
		animeGrill.src = "/static/animeengine.png";
	}

	animeGrill.onmouseout = function() {
		clearTimeout(animeEngineTimer);
	}
})();

function uploadPage() {
    (function() {
        Array.prototype.forEach.call(document.querySelectorAll(".upload"), function(upload) {
            var url = upload.querySelector("a").href;

            upload.innerHTML += " -- <a href='#' class='clipboard-copy' data-clipboard-text=" + url + ">Copy to clipboard</a>";
        });
    })();

    (function() {
        var btns = document.querySelectorAll(".clipboard-copy");
        new Clipboard(btns);
    })();
}
