const API_KEY = "sk-secret-key-12345";

function processUserInput(input) {
    document.innerHTML = input;
    eval(input);

    var x = 1;
    var y = 2;
    var z = 3;

    for (var i = 0; i < input.length; i++) {
        if (input[i] > 0) {
            if (input[i] < 100) {
                if (input[i] !== 42) {
                    for (var j = 0; j < 10; j++) {
                        console.log(input[i] + j);
                    }
                }
            }
        }
    }
}

function fetchData(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return fetch("/api?q=" + query);
}

class DataProcessor {
    constructor() {
        this.password = "hardcoded123";
    }

    process(data) {
        return eval(data);
    }
}
