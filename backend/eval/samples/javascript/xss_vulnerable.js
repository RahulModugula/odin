function renderUserProfile(userData) {
    document.getElementById("profile").innerHTML = userData.bio;
    document.getElementById("name").innerHTML = "<h1>" + userData.name + "</h1>";

    const script = document.createElement("script");
    script.textContent = userData.customScript;
    document.body.appendChild(script);
}

function handleSearch(query) {
    const resultsDiv = document.getElementById("results");
    resultsDiv.innerHTML = "Results for: " + query;

    eval("processQuery('" + query + "')");
}
