from flask import Flask, jsonify, render_template, request
from flask import session as login_session
from sqlalchemy.orm import sessionmaker
import json
import models
from sqlalchemy import create_engine
import contextlib
import random, string

# IMPORTS FOR THIS STEP
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

engine = create_engine('postgresql:///catalog')
Session = sessionmaker(bind=engine)
Session.configure(bind=engine)

app = Flask(__name__)

def get_nonce() : 
	nonce = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
	login_session["state"] = nonce

	return nonce

@contextlib.contextmanager
def get_cursor():
    """
    This function is responsible for returning a cursor instance 
    by using the context manager and the above decorator
    """
    session = Session()

    try:
        yield session
    except:
        raise
    else:
        session.commit()

"""first seed the test data """
with open('data.json') as data_file:     
    data 			= json.load(data_file)

with get_cursor() as session :
	categories 		= [];
	items 			= [];

	for categoryJSON in data["categories"] :
		category = models.Category(name=categoryJSON["name"])
		categories.append(category)

	for itemJSON in data["items"] :
		item = models.Item(name=itemJSON["name"], description=itemJSON["description"], category_id=itemJSON["category_id"])
		items.append(item)

	session.add_all(categories)
	session.add_all(items);

"""BELOW ARE ALL HTML ENDPOINTS"""

@app.route('/', methods=['GET'])
def latest_items():
    return render_template('list.html')

@app.route('/<category>/items', methods=['GET'])
def category_items(category) :
	return 'Hello World!'

@app.route('/<category>/<item>', methods=['GET'])
def category_item(category, item) :
	return 'Hello World!'

@app.route('/<category>/<item>/edit', methods=['GET'])
def edit_item(category, item) :
	return 'Hello World!'

@app.route('/<category>/<item>/delete', methods=['GET'])
def delete_item(category, item) :
	return 'Hello World!'

@app.route('/login', methods=['GET'])
def login() :
	
	state = get_nonce()
	return render_template('login.html', state = state)

""" BELOW ARE ALL JSON API ENDPOINTS """

"""CATEGORIES"""

def jsonify_categories(list) :
	return jsonify(categories=[category.serialize() for category in list])


@app.route('/json/category/list')
def JSON_list_categories() :
	with get_cursor() as session :
		categories = session.query(models.Category)
		
	return jsonify_categories(categories)

@app.route('/json/category/<int:id>', methods = ['GET'])
def JSON_get_category(id) :
	with get_cursor() as session :
		categories = session.query(models.Category).filter(models.Category.id == id)

	return jsonify_categories(categories)

@app.route('/json/category/<int:id>', methods = ['POST'])
def JSON_create_category() :
	return 'Hello World!'

@app.route('/json/category/<int:id>', methods = ['PUT'])
def JSON_update_category() :
	return 'Hello World!'

@app.route('/json/category/<int:id>', methods = ['DELETE'])
def JSON_delete_category() :
	return 'Hello World!'

"""ITEMS"""

def jsonify_items(list) :
	return jsonify(items=[item.serialize() for item in list])

@app.route('/json/items/list')
def JSON_list_items() :
	with get_cursor() as session :
		items = session.query(models.Item)
		
	return jsonify_items(items)

@app.route('/json/items/latest')
def JSON_latest_items() :
	with get_cursor() as session :
		items = session.query(models.Item).limit(5)
		
	return jsonify_items(items)

@app.route('/json/items/<int:id>', methods = ['GET'])
def JSON_get_item(id) :
	with get_cursor() as session :
		items = session.query(models.Item).filter(models.Item.id == id)

	return jsonify_items(items)

@app.route('/json/items/<int:id>', methods = ['POST'])
def JSON_create_items() :
	return 'Hello World!'

@app.route('/json/items/<int:id>', methods = ['PUT'])
def JSON_update_items() :
	return 'Hello World!'

@app.route('/json/items/<int:id>', methods = ['DELETE'])
def JSON_delete_items() :
	return 'Hello World!'

"""Below is the Gconnect function for google connect"""
@app.route('/json/gconnect', methods=['POST'])
def gconnect():

    # Validate state token
	if request.args.get('state') != login_session['state'] :
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'

		return response

	# Obtain authorization code
	code = request.data

	try:
	    # Upgrade the authorization code into a credentials object
	    oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
	    oauth_flow.redirect_uri = 'postmessage'
	    credentials = oauth_flow.step2_exchange(code)
	except FlowExchangeError:
	    response = make_response(
	        json.dumps('Failed to upgrade the authorization code.'), 401)
	    response.headers['Content-Type'] = 'application/json'
	    return response


if __name__ == '__main__':
	app.debug = True
	app.secret_key = 'super secret key'
	app.run(host='0.0.0.0')