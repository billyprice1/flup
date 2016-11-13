function loadImage(url, callback) {
    var img = new Image();
    img.src = url;

	img.onload = callback;
}

(function() {
	var animeGrill = document.getElementById("anime");
	var animeEngineTimer = null;

	animeGrill.onmouseover = function() {
		animeEngineTimer = setTimeout(function() {
			loadImage("/static/animeengine.png", function() {
				animeGrill.src = "/static/animeengine.png";
			});
		}, 5000);
	}

	animeGrill.onmouseout = function() {
		clearTimeout(animeEngineTimer);
	}
})();

function uploadPage() {
    (function() {
        Array.prototype.forEach.call(document.querySelectorAll(".upload"), function(upload) {
            var url = upload.querySelector("a").innerHTML;

            upload.innerHTML += " -- <a href='#' class='clipboard-copy' data-clipboard-text=" + url + ">Copy to clipboard</a>";
        });
    })();

    (function() {
        var btns = document.querySelectorAll(".clipboard-copy");
        new Clipboard(btns);
    })();
}
