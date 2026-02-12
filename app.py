from flask import Flask, render_template, request
import random

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        result = random.randint(70, 99)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run()
