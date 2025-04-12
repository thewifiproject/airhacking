from flask import Flask, request, render_template_string

app = Flask(__name__)

# HTML login form embedded directly in Python
HTML = """
<!doctype html>
<html>
<head>
    <title>Test Login Page</title>
</head>
<body>
    <h2>Login</h2>
    <form method="POST" action="/login">
        Username: <input type="text" name="username" /><br><br>
        Password: <input type="password" name="password" /><br><br>
        <input type="submit" value="Login" />
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    print(f"[LOGIN ATTEMPT] Username: {username}, Password: {password}")
    return "Login submitted!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
