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
