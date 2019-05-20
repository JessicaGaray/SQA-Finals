import os
import json
import datetime
import hashlib
import binascii
from flask import Flask
from flask import render_template
from flask import redirect
from flask import request
from flask import session
from flask import url_for
from flask import make_response
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = '///'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///appdata.sqlite3'

db = SQLAlchemy(app)

class User(db.Model):
	username = db.Column(db.String(128), unique = True, primary_key = True, nullable = False)
	password = db.Column(db.String(), nullable = False)

init_contact = { 'id': None,
			'firstname': None,
			'lastname': None,
			'phonenumber': None,
			'emailaddress': None,
			'birthdate': None,
			'note': None }

def get_and_clear_error():
	if 'error' in session:
		error = session['error']
		del session['error']
		return error
	return None
app.jinja_env.globals.update(get_and_clear_error=get_and_clear_error)

def hash_password(password):
	salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
	pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
									salt, 100000)
	pwdhash = binascii.hexlify(pwdhash)
	return (salt + pwdhash).decode('ascii')

def verify_password(stored_password, provided_password):
	salt = stored_password[:64]
	stored_password = stored_password[64:]
	pwdhash = hashlib.pbkdf2_hmac('sha512',
									provided_password.encode('utf-8'),
									salt.encode('ascii'),
									100000)
	pwdhash = binascii.hexlify(pwdhash).decode('ascii')
	return pwdhash == stored_password

@app.route('/sandbox')
def sandbox():
	users = User.query.all()
	output = ''
	for user in users:
		output += user.username
		output += user.password
	return output

def initialise_app():
	db.create_all()

	sudo_user = User(username = 'sudo',
				password = 'sudo')
	db.session.add(sudo_user)
	db.session.commit()
	return 'OK'

def initialise_contacts():
	if 'username' not in session:
		return 'Error'

	import os.path
	if not os.path.isfile('appdata_' + str(session['username']) + '.md'):
		with open('appdata_' + str(session['username']) + '.md', 'w+') as data_file:
			pass

	with open('appdata_' + str(session['username']) + '.md', 'r') as data_file:
		if data_file.read(1) == '':
			data = []
			initContact = dict(init_contact)
			initContact['id'] = 0
			data.append(initContact)
			app.logger.info('Initial contact created.')

			with open('appdata_' + str(session['username']) + '.md', 'w') as data_file:
				data_file.write(json.dumps(data))
			app.logger.info('Data file written.')
	with open('appdata_' + str(session['username']) + '.md', 'r') as data_file:
		return json.loads(data_file.read())

@app.route('/login')
def _view_login():
	if 'username' in session and session['username'] is not '':
		return redirect(url_for('_view_index'))
	return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_user():
	while True:
		if 'username' not in request.form or 'password' not in request.form:
			session['error'] = "All fields are required."
			break
		if request.form['username'] is '' or request.form['password'] is '':
			session['error'] = "All fields are required."
			break
		if User.query.filter_by(username=request.form['username']).first() is None:
			session['error'] = "This user does not exist."
			break
		user = User.query.filter_by(username=request.form['username']).first()
		if not verify_password(user.password, request.form['password']):
			session['error'] = "Incorrect password entered."
			break
		break
	if 'error' in session:
		return redirect(url_for('_view_login'))

	session['username'] = user.username
	return redirect(url_for('_view_index'))

@app.route('/logout')
def logout_user():
	if 'username' in session and session['username'] is not '':
		del session['username']
	return redirect(url_for('_view_login'))

@app.route('/signup')
def _view_signup():
	if 'username' in session and session['username'] is not '':
		return redirect(url_for('_view_index'))
	return render_template('signup.html')

@app.route('/signup', methods=['POST'])
def register_user():
	while True:
		if 'username' not in request.form or 'password' not in request.form:
			session['error'] = "All fields are required."
			break
		if User.query.filter_by(username=request.form['username']).first():
			session['error'] = "This user already exists."
			break
		break
	if 'error' in session:
		return redirect(url_for('_view_signup'))

	user = User(username = request.form['username'],
				password = hash_password(request.form['username']))

	db.session.add(user)
	db.session.commit()

	session['username'] = user.username
	return redirect(url_for('_view_index'))

@app.route('/')
def _view_index():
	if 'username' not in session:
		return redirect(url_for('_view_login'))

	data = initialise_contacts()
	if len(data) <= 0:
		data = []
	return render_template('index.html', data=data)

@app.route('/contact', methods=['POST'])
def new_contact():
	if 'username' not in session:
		return 'Error'

	data = initialise_contacts()
	if 'id' in request.form:
		if request.form['id'] is '':
			contact = dict(init_contact)
			if 'firstname' in request.form:
				contact['firstname'] = request.form['firstname']
			if 'lastname' in request.form:
				contact['lastname'] = request.form['lastname']
			if 'phonenumber' in request.form:
				contact['phonenumber'] = request.form['phonenumber']
			if 'emailaddress' in request.form:
				contact['emailaddress'] = request.form['emailaddress']
			if 'birthdate' in request.form:
				contact['birthdate'] = request.form['birthdate']
			if 'note' in request.form:
				contact['note'] = request.form['note']
			if contact == init_contact:
				app.logger.error('All fields are empty.')
				return 'Error'
			contact['id'] = data[0]['id']
			data.append(contact)
			data[0]['id'] = data[0]['id'] + 1
			app.logger.info('New contact added locally.')
		else:
			for contact in data:
				if contact['id'] is int(request.form['id']):
					if 'firstname' in request.form:
						contact['firstname'] = escape(request.form['firstname'])
					if 'lastname' in request.form:
						contact['lastname'] = escape(request.form['lastname'])
					if 'emailaddress' in request.form:
						contact['emailaddress'] = escape(request.form['emailaddress'])
					if 'phonenumber' in request.form:
						contact['phonenumber'] = escape(request.form['phonenumber'])
					if 'birthdate' in request.form:
						contact['birthdate'] = escape(request.form['birthdate'])
					if 'note' in request.form:
						contact['note'] = escape(request.form['note'])
					app.logger.info('Contact edited locally.')
					break
	with open('appdata_' + str(session['username']) + '.md', 'w') as data_file:
		data_file.write(json.dumps(data))
	app.logger.info('Data file written.')
	return 'OK'

@app.route('/delete', methods=['POST'])
def delete_contact():
	if 'username' not in session:
		return 'Error'

	if 'id' not in request.form:
		return False
	inputId = int(request.form['id'])
	with open('appdata_' + str(session['username']) + '.md', 'r') as data_file:
		data = json.loads(data_file.read())
	data = [t for t in data if not (t['id'] is inputId)]
	with open('appdata_' + str(session['username']) + '.md', 'w') as data_file:
		data_file.write(json.dumps(data))
	return 'OK'

if __name__ == "__main__":
	app.run(host="0.0.0.0", debug=True)
