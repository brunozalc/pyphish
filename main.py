import os

from flask import Flask, jsonify, render_template, request

from detector import PhishingDetector

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-key-change-in-production")

detector = PhishingDetector()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        data = request.get_json()
        url = data.get("url", "").strip()

        if not url:
            return jsonify(
                {"error": True, "message": "Por favor, forneça uma URL para análise"}
            ), 400

        check_lists = data.get("check_lists", True)

        results = detector.analyze_url(url, check_lists=check_lists)

        return jsonify({"error": False, "results": results})

    except Exception as e:
        return jsonify(
            {"error": True, "message": f"Erro ao analisar URL: {str(e)}"}
        ), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": True, "message": "Endpoint não encontrado"}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": True, "message": "Erro interno do servidor"}), 500


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Credentials"] = "true"
    else:
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers.pop("Access-Control-Allow-Credentials", None)

    response.headers.setdefault(
        "Access-Control-Allow-Headers", "Content-Type, Authorization"
    )
    response.headers.setdefault(
        "Access-Control-Allow-Methods", "GET, POST, OPTIONS"
    )
    return response


if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)
    os.makedirs("static", exist_ok=True)

    app.run(debug=True, host="0.0.0.0", port=5000)
