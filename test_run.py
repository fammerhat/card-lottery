from flask import Flask

print(">>> test_run.py 已被執行")

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello, Flask is running!"

if __name__ == "__main__":
    print("__name__ =", __name__)
    print("準備呼叫 app.run() ...")
    app.run(debug=True)