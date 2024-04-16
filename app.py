from flask import Flask, request, jsonify, make_response, render_template, session, redirect, url_for
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '\xc8\x06\xb6\xd6\xb0\x87\x03>\xc2\r?\x85'


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'Alert': 'Token is missing'}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'])
        except jwt.ExpiredSignatureError:
            return jsonify({'Alert': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'Alert': 'Invalid Token!'}), 401
        return func(*args, **kwargs)

    return decorated


@app.route('/')
def home():
    if not session.get("logged_in"):
        return render_template('login.html')
    else:
        return render_template('home.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


@app.route('/public')
def public():
    return 'For Public'


@app.route('/auth')
@token_required
def auth():
    return 'JWT is verified. Welcome to the page'


@app.route('/login', methods=['POST'])
def login():
    if request.form['username'] == 'username' and request.form['password'] == 'password':
        session['logged_in'] = True

        token = jwt.encode({
            'user': request.form['username'],
            'exp': datetime.utcnow() + timedelta(minutes=30)
        },
            app.config['SECRET_KEY']
        )
        return jsonify({'token': token.decode('utf-8')})  # Decode the token for JSON serialization
    else:
        return make_response('Unable to verify', 403, {'WWW-Authenticate': 'Basic realm="Authentication Failed!"'})


if __name__ == "__main__":
    app.run(debug=True)