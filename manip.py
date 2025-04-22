# secure_web.py
from flask import Flask, request, redirect, url_for, render_template_string

app = Flask(__name__)

USERNAME = "admin"
PASSWORD = "SP-91862D361"

login_form = """
<html>
<head><title>Přihlášení</title></head>
<body style="font-family:sans-serif;text-align:center;margin-top:50px;">
    <h2>🔐 Přihlášení</h2>
    <form method="POST">
        <input type="text" name="username" placeholder="Uživatel"><br><br>
        <input type="password" name="password" placeholder="Heslo"><br><br>
        <input type="submit" value="Přihlásit">
    </form>
    {% if error %}
        <p style="color:red;">{{ error }}</p>
    {% endif %}
</body>
</html>
"""

dashboard = """
<html>
<head><title>Dashboard</title></head>
<body style="font-family:sans-serif;text-align:center;margin-top:50px;">
    <h1>✅ Přihlášeno jako admin</h1>
    <p>Vítej na chráněné stránce!</p>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] == USERNAME and request.form['password'] == PASSWORD:
            return render_template_string(dashboard)
        else:
            error = "Neplatné přihlašovací údaje!"
    return render_template_string(login_form, error=error)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
