from flask import Flask, request, render_template_string, redirect, url_for, abort
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# HTML template for the index page
INDEX_HTML = """
<!doctype html>
<html>
<head>
    <title>Upload & Read File</title>
</head>
<body>
    <h1>Upload a File</h1>

    <form method="POST" action="{{ url_for('upload_file') }}" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <input type="submit" value="Upload">
    </form>

    {% if upload_msg %}
        <p>{{ upload_msg }}</p>
    {% endif %}

    <hr>

    <h1>Read an Uploaded File</h1>

    <form method="POST" action="{{ url_for('read_uploaded_file') }}">
        <input type="text" name="filename" placeholder="Enter filename" required>
        <button type="submit">Read file</button>
    </form>

    {% if content %}
        <h2>File Contents</h2>
        <pre>{{ content }}</pre>
    {% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML)

@app.route("/read", methods=["POST"])
def read_uploaded_file():
    filename = request.form.get("filename")
    if not filename:
        abort(400, "Missing filename")
    
    if '..' in filename or '.p' in filename:
        abort(400, "Illegal filename")

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    if not os.path.isfile(file_path):
        abort(404, "File not found")

    with open(file_path, "r", errors="replace") as f:
        content = f.read()

    return render_template_string(
        INDEX_HTML,
        content=content
    )

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        abort(400, "No file part")

    file = request.files["file"]

    if file.filename == "":
        abort(400, "No selected file")
    
    if '..' in file.filename or '.p' in file.filename:
        abort(400, "Illegal filename")

    save_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(save_path)

    # Return the same index page with success message
    return render_template_string(
        INDEX_HTML,
        upload_msg=f"{file.filename} uploaded successfully"
    )

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0")