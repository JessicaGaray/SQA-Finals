import json
from flask import Flask, render_template, redirect, request, jsonify, session, url_for, make_response, escape

app = Flask(__name__)

init_contact = { 'id': None, 
			'firstname': None, 
			'lastname': None, 
			'phonenumber': None, 
			'emailaddress': None, 
			'birthdate': None, 
			'note': None }

def initialise_contacts():
	with open('appdata.md', 'r') as data_file:
		if data_file.read(1) == '':
			data = []
			initContact = dict(init_contact)
			initContact['id'] = 0
			data.append(initContact)
			app.logger.info('Initial contact created.')
		
			with open('appdata.md', 'w+') as data_file:
				data_file.write(json.dumps(data))
			app.logger.info('Data file written.')
	with open('appdata.md', 'r') as data_file:
		return json.loads(data_file.read())

@app.route('/')
def _view_index():
	data = initialise_contacts()
	if len(data) <= 0:
		data = []
	return render_template('index.html', data=data)

@app.route('/contact', methods=['POST'])
def new_contact():
	data = initialise_contacts()
	if 'id' in request.form:
		if request.form['id'] is '':
			contact = dict(init_contact)
			if 'firstname' in request.form:
				contact['firstname'] = escape(request.form['firstname'])
			if 'lastname' in request.form:
				contact['lastname'] = escape(request.form['lastname'])
			if 'phonenumber' in request.form:
				contact['phonenumber'] = escape(request.form['phonenumber'])
			if 'emailaddress' in request.form:
				contact['emailaddress'] = escape(request.form['emailaddress'])
			if 'birthdate' in request.form:
				contact['birthdate'] = escape(request.form['birthdate'])
			if 'note' in request.form:
				contact['note'] = escape(request.form['note'])
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
	with open('appdata.md', 'w') as data_file:
		data_file.write(json.dumps(data))
	app.logger.info('Data file written.')
	return 'OK'
					
@app.route('/delete', methods=['POST'])
def delete_contact():
	if 'id' not in request.form:
		return False
	inputId = int(request.form['id'])
	with open('appdata.md', 'r') as data_file:
		data = json.loads(data_file.read())
	data = [t for t in data if not (t['id'] is inputId)]
	with open('appdata.md', 'w') as data_file:
		data_file.write(json.dumps(data))
	return 'OK'

if __name__ == "__main__":
	app.run(host="0.0.0.0", debug=True)