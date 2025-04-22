from flask import Flask, request, redirect, url_for, render_template_string, session

app = Flask(__name__)
app.secret_key = "tajny_klic_123"  # pro session management

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
            session['user'] = USERNAME
            return redirect(url_for('dashboard_view'))
        else:
            error = "Neplatné přihlašovací údaje!"
    return render_template_string(login_form, error=error)

@app.route('/dashboard')
def dashboard_view():
    if session.get('user') == USERNAME:
        return render_template_string(dashboard)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
