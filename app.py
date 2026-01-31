import os
from flask import Flask, jsonify

app = Flask(__name__)

@app.get("/")
def home():
    return """
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Railway Flask App</title>
        <style>
          body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 40px; }
          code { background: #f2f2f2; padding: 2px 6px; border-radius: 6px; }
          .card { border: 1px solid #e6e6e6; border-radius: 12px; padding: 18px; max-width: 720px; }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>✅ Deployed on Railway</h1>
          <p>This is a minimal <b>Flask</b> website.</p>
          <p>Try: <code>/health</code></p>
        </div>
      </body>
    </html>
    """

@app.get("/health")
def health():
    return jsonify(status="ok")

if __name__ == "__main__":
    # Railway provides PORT; fall back to 8000 locally.
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
