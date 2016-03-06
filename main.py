from flask import Flask, jsonify, render_template, request, make_response, flash, abort
from flask import redirect, url_for, send_from_directory
from flask import session as login_session
from sqlalchemy.orm import sessionmaker, joinedload
import json, models,  random, string, os
from sqlalchemy import create_engine
import contextlib
import xml.etree.ElementTree as ET
import functools

# IMPORTS FOR THIS STEP
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import httplib2
import requests, time
import urllib
from werkzeug import secure_filename
from werkzeug.contrib.atom import AtomFeed
import seeder, datetime


engine = create_engine('postgresql:///catalog')
Session = sessionmaker(bind=engine)
Session.configure(bind=engine)
session = Session()
JSON_URL = 'http://localhost:5000'
UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
MAX_FILE_SIZE = 8 * 1024 * 1024

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

'''Create a response to 400, 401, 403 requests '''
@app.errorhandler(401)
def unauthorised(error) :
	flash('You must be logged in to view this item.')
	return redirect('/')

@app.errorhandler(400)
def unauthorised(error) :
	flash('There was an error loading that page')
	return redirect('/')

@app.errorhandler(403)
def unauthorised(error) :
	flash('Your are not the owner of that item')
	return redirect('/')

'''the below creates an atom feed of all of the items on the catalog'''
@app.route('/list.atom')
def recent_feed():
	feed = AtomFeed('Recent Items',
	feed_url=request.url, url=request.url_root)
	items = session.query(models.Item).options(joinedload('category')).all()
	


	for item in items:
		feed.add(item.name, unicode(item.description),
		content_type='html',
		category=item.category,
		picture=item.picture,
		id=item.id,
		updated=item.updated,
		published=item.created
		)
	
	return feed.get_response()

'''Set what file types are allowed for upload '''
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

'''set the nonce for the user and return it to the method calling it. 
This is used to prevent cross site attacks'''
def get_nonce() : 
	nonce = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
	login_session["state"] = nonce

	return nonce

'''get the access token by ID'''
def get_access_token(user_id) :
	try :
		expires = datetime.date.today() + datetime.timedelta(days=1)
		token = session.query(models.AccessToken).filter(models.AccessToken.expires > expires)
		token = token.filter(models.AccessToken.user_id == user_id).one().get()
		return token
	except : 
		return None

'''get an access token by its code'''
def get_access_token_by_token(code) :
	try :
		expires = datetime.date.today() + datetime.timedelta(days=1)
		token = session.query(models.AccessToken).filter(models.AccessToken.expires > expires).filter(models.AccessToken.token == code).one()
		return token
	except : 
		return None

'''insert an access token into the database for a given user'''
def create_access_token(user_id) :
	nonce = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
	expires = datetime.date.today() + datetime.timedelta(days=1)
	token = models.AccessToken(user_id = user_id, token=nonce, created = time.strftime("%d/%m/%Y"), expires= expires.strftime("%d/%m/%Y"))
	session.add(token)
	session.commit()

	return token

def json_response(code, message) :
	response = make_response(json.dumps(message), code)
	response.headers['Content-Type'] = 'application/json'
	return response

'''check if the user is logged in, redirect them if not.
This should really be check against an authorisation token stored on the client.'''
def check_login(func) :
	@functools.wraps(func)
	def func_wrapper(*args, **kwargs):
		if 'access_token' not in login_session :
			abort(401)

		return func(*args, **kwargs)
	return func_wrapper
	

''' chec if the user has the correct nonce '''
def check_state(func) :
	@functools.wraps(func)
	def func_wrapper(*args, **kwargs):

		if 'state' not in login_session :
			abort(400)

		if login_session['state'] != request.args.get('state') and ('state' not in request.form or login_session['state'] != request.form['state'] ) :
			abort(400)

		return func(*args, **kwargs)
	return func_wrapper

'''This function is used on all JSON endpoints that require 
an authorised request to come from a logged in user'''
def check_access_token(func) :
	@functools.wraps(func)
	def func_wrapper(*args, **kwargs):
		try :
			if 'access-token' not in request.headers :
				return json_response(401, "Your are not not logged in")
			
			expires = datetime.date.today() + datetime.timedelta(days=1)
			token_count = session.query(models.AccessToken).filter(models.AccessToken.expires > expires)
			token_count = token_count.filter(models.AccessToken.token == request.headers['access-token']).count()
			
			if token_count > 0 :
				return func(*args, **kwargs)
			else :
				return json_response(401, "Your are not not logged in")


		except :
			return json_response(401, "Your are not not logged in")

	return func_wrapper

'''Generate the user row in our database when they login for the first time with google / facebook '''
def createUser(login_session) :
	newUser = models.User(name = login_session['username'], 
		email = login_session['email'], picture=login_session['picture'])
	
	session.add(newUser)
	session.commit()
	
	user = session.query(models.User).filter_by(email = login_session['email']).one()
	return user.id

'''return the user info based on their ID'''
def getUserInfo(user_id) :
	try :
		user = session.query(models.User).filter_by(id=user_id).first()
		return user
	except:
		return None

'''return the user ID based on their email'''
def getUserID(user_email) :
	try:
		user = session.query(models.User).filter_by(email=user_email).one()
		return user.id
	except:
		return None

"""BELOW ARE ALL HTML ENDPOINTS"""


'''this is used to help generate the filename'''
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

'''show the home page template. All content is loaded from JSON end points'''
@app.route('/', methods=['GET'])
def latest_items():
	data = requests.get(JSON_URL + '/json/item/latest')
	data = json.loads(data.text)

	category_data = requests.get(JSON_URL + '/json/category/list')
	category_data = json.loads(category_data.text)

	return render_template('list.html', items=data['items'], 
		categories=category_data['categories'])

'''show a specific category with all of the items in it'''
@app.route('/category/<category>', methods=['GET'])
def view_category(category) :
	data = requests.get(JSON_URL + '/json/category/' + category)
	data = json.loads(data.text)

	category_data = requests.get(JSON_URL + '/json/category/list')
	category_data = json.loads(category_data.text)

	return render_template('category/list.html', category = data['categories'], 
		categories=category_data['categories'])

'''show a specific item and all of its information'''
@app.route('/item/<item>', methods=['GET'])
def view_item(item) :
	data = requests.get(JSON_URL + '/json/item/' + str(item))
	data = json.loads(data.text)

	state = get_nonce()

	category_data = requests.get(JSON_URL + '/json/category/list')
	category_data = json.loads(category_data.text)

	return render_template('item/list.html', item = data['items'], 
		categories=category_data['categories'], state = state)

'''show the form to edit an item'''
@app.route('/item/<int:item>/edit', methods=['GET'])
@check_login
def edit_item(item) :

	item_data = requests.get(JSON_URL + '/json/item/' + str(item))
	item_data = json.loads(item_data.text)
	item_data = item_data['items']
	db_id = item
	

	category_data = requests.get(JSON_URL + '/json/category/list')
	category_data = json.loads(category_data.text)

	state = get_nonce()
	return render_template('item/edit.html', id = db_id, item = item_data, 
		categories = category_data['categories'], state = state)


'''show the same template as above, mock up an empty item to 
prevent errors in the form and set the ID to false / 0 so that the 
server know's to call the POST endpoint & not PUT'''

@app.route('/item/add', methods=['GET'])
@check_login
def add_item() :
	db_id = False

	item_data = {
		'name' : '',
		'description' : '',
		'category_id' : -1
	}
	

	category_data = requests.get(JSON_URL + '/json/category/list')
	category_data = json.loads(category_data.text)

	state = get_nonce()
	return render_template('item/edit.html', id = db_id, item = item_data, 
		categories = category_data['categories'], state = state)

'''this method is where the above form is actually posted to. All of the info is 
loaded & we check if the user is logged in and is posting from our site (nonce), 
otherwise redirect them'''

@app.route('/item/update/<int:id>', methods=['POST'])
@check_login
@check_state
def post_item(id) :
	'''either load the image thumbnail if it's a new item, or 
	load the current items image if we're updating'''
	if id == 0 :
		picture_url = url_for('uploaded_file',filename='thumb.jpg')
	else :
		data = requests.get(JSON_URL + '/json/item/' + str(id))
		data = json.loads(data.text)
		picture_url = data['items']['picture']

	'''If a file has been uploaded, save it to uploads & set it as the picture variable'''
	if 'picture' in request.files :

		file = request.files['picture']
		if file and allowed_file(file.filename):
			filename = secure_filename(file.filename)
			file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
			picture_url = url_for('uploaded_file',filename=filename)

	'''create the json data we are going to post on'''
	item_data = {
		'picture' : picture_url,
		'name' : request.form['name'],
		'description' : request.form['description'],
		'category_id' : request.form['category'],
		'user_id' : login_session['user_id']
	}

	headers = {'content-type': 'application/json', 'access-token' : login_session['access_token']}

	response = None


	'''make the necessary posts to our JSON api. Either to update 
	the current item if id > 0 or create a new item '''
	if id == 0 :
		response = requests.post(JSON_URL + '/json/item', data= json.dumps(item_data, cls=models.CustomJSONEncoder), headers=headers)
	else :
		item_data['id'] = id
		response = requests.put(JSON_URL + '/json/item/' + str(id), data= json.dumps(item_data, cls=models.CustomJSONEncoder), headers=headers)
		

	'''redirect and show a message'''

	if response.status_code == 200 :
		flash('That item was successfully created / updated')
		return redirect('/')
	else :
		abort(response.status_code)
		
'''the below function deletes an item by querying the JSON API'''
@app.route('/item/<item>/delete/', methods=['GET'])
@check_login
@check_state
def delete_item(item) :
	
	headers = {'content-type': 'application/json', 'access-token' : login_session['access_token']}
	data = requests.delete(JSON_URL + '/json/item/' + item, headers = headers)
	if data.status_code == 200 :
		flash('Item successfully deleted')
		return redirect('/')

	abort(data.status_code)


'''show the login form'''
@app.route('/login', methods=['GET'])
def login() :
	
	if 'username' in login_session :
		flash('You are already logged in')
		return redirect('/')

	state = get_nonce()
	return render_template('login.html', state = state)

""" BELOW ARE ALL JSON API ENDPOINTS """

"""CATEGORIES"""
@app.route('/json/category/list')
def JSON_list_categories() :
	categories = session.query(models.Category).all()
		
	return json.dumps({'categories':categories}, cls=models.CustomJSONEncoder)

@app.route('/json/category/<int:id>', methods = ['GET'])
def JSON_get_category(id) :
	categories = session.query(models.Category).options(joinedload('items')).filter(models.Category.id == id).one()

	return json.dumps({'categories': categories}, cls=models.CustomJSONEncoder)

"""ITEMS"""


@app.route('/json/item/list')
def JSON_list_items() :
	items = session.query(models.Item).options(joinedload('category')).all()
		
	return json.dumps({'items': items}, cls=models.CustomJSONEncoder)

@app.route('/json/item/latest')
def JSON_latest_items() :
	items = session.query(models.Item).options(joinedload('category')).limit(5).all()
	
	return json.dumps({'items': items}, cls=models.CustomJSONEncoder)

@app.route('/json/item/<int:id>', methods = ['GET'])
def JSON_get_item(id) :
	items = session.query(models.Item).options(joinedload('category')).filter(models.Item.id == id).one()
	return json.dumps({'items': items}, cls=models.CustomJSONEncoder)

@app.route('/json/item', methods = ['POST'])
@check_access_token
def JSON_create_item() :

	item = models.Item(name= request.json['name'], picture= request.json['picture'],
		user_id= request.json['user_id'], category_id= request.json['category_id'],
		description= request.json['description'], created = time.strftime("%d/%m/%Y"), updated= time.strftime("%d/%m/%Y"))
	session.add(item)
	session.commit()



	return json_response(200, "")

@app.route('/json/item/<int:id>', methods = ['PUT'])
@check_access_token
def JSON_update_item(id) :
	'''check the user owns the item'''
	item = session.query(models.Item).filter(models.Item.id == id).one()

	token = get_access_token_by_token(request.headers['access-token'])

	if token.user_id != item.user_id :
		return json_response(401, "Your are not authorised to perform that action")

	item.picture = request.json['picture']
	item.name = request.json['name']
	item.description = request.json['description']
	item.category_id = request.json['category_id']
	item.updated = time.strftime("%d/%m/%Y")
	
	session.add(item)
	session.commit()
	
	return json.dumps({'result' :  True})

@app.route('/json/item/<int:id>', methods = ['DELETE'])
@check_access_token
def JSON_delete_item(id) :

	'''check the user owns the item'''
	item = session.query(models.Item).filter(models.Item.id == id).one()
	token = get_access_token_by_token(request.headers['access-token'])

	if token.user_id != item.user_id :
		return json_response(401, "Your are not authorised to perform that action")

	session.query(models.Item).filter_by(id=id).delete()
	session.commit()


	return json.dumps({'result' : True})

'''handle connecting to facebook'''
@app.route('/json/fbconnect', methods=['POST'])
def fbconnect():
	'''validate the nonce'''
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	access_token = request.data
	print "access token received %s " % access_token

	'''load our FB APP data'''
	app_id = json.loads(open('fb_client_secret.json', 'r').read())[
		'web']['app_id']
	app_secret = json.loads(
	open('fb_client_secret.json', 'r').read())['web']['app_secret']
	url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
	app_id, app_secret, access_token)
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]

	# Use token to get user info from API
	userinfo_url = "https://graph.facebook.com/v2.4/me"
	# strip expire tag from access token
	token = result.split("&")[0]


	url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
	h = httplib2.Http()

	'''get the result (user) and set their session data'''
	result = h.request(url, 'GET')[1]
	# print "url sent for API access:%s"% url
	# print "API JSON result: %s" % result
	data = json.loads(result)
	login_session['provider'] = 'facebook'
	login_session['username'] = data["name"]
	login_session['email'] = data["email"]
	login_session['facebook_id'] = data["id"]

	# The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
	stored_token = token.split("=")[1]
	login_session['access_token'] = stored_token

	# Get user picture
	url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
	h = httplib2.Http()
	result = h.request(url, 'GET')[1]
	data = json.loads(result)

	login_session['picture'] = data["data"]["url"]

	'''check if a user exists, if not insert them into the database'''
	# see if user exists
	user_id = getUserID(login_session['email'])

	if not user_id:
		user_id = createUser(login_session)
	
	login_session['user_id'] = user_id

	'''check if there is an active access token to set to the user '''
	token = get_access_token(user_id)

	if token is None :
		token = create_access_token(user_id)

	login_session['access_token'] = token.token

	flash('You are now logged in as ' + login_session['username'])
	response = make_response(json.dumps(True), 200)
	response.headers['Content-Type'] = 'application/json'
	return response

"""Below is the Gconnect function for google connect"""
@app.route('/json/gconnect', methods=['POST'])
def gconnect():
	CLIENT_ID = "712697227714-82l7i402jl1uqhr2gqr37iok2ib25io4.apps.googleusercontent.com"
    # Validate state token
	if request.args.get('state') != login_session['state'] :
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	# Obtain authorization code
	code = request.data
	code = code.replace('"', "")

	# Upgrade the authorization code into a credentials object
	try:
	    oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
	    oauth_flow.redirect_uri = 'postmessage'
	    credentials = oauth_flow.step2_exchange(code)
	except FlowExchangeError, e:
	    response = make_response(json.dumps(str(e)), 401)
	    response.headers['Content-Type'] = 'application/json'
	    return response



	#check the access token is valid
	access_token = credentials.access_token
	url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)

	h = httplib2.Http()
	result = json.loads(h.request(url, 'GET')[1])

	#if there was an error in the access token info, abort
	if result.get('error') is not None:
		response = make_response(json.dumps(result.get('error')), 50)
		response.headers['Content-Type'] = 'application/json'
		return response



	#verify the access token is used for the intended user
	gplus_id =  credentials.id_token['sub']
	if result['user_id'] != gplus_id :
		response = make_response(json.dumps("Token's user ID does not match given user ID"), 401)
		response.headers['Content-Type'] = 'application/json'
		return response



	#verify access token is valid for this app
	if result['issued_to'] != CLIENT_ID:
		response = make_response(json.dumps("Token's client ID does not match app's"), 401)
		response.headers['Content-Type'] = 'application/json'
		print "Token's client ID does not match app's"
		return response




	#check to see if user is already logged in
	stored_credentials =  login_session.get('credentials')
	stored_gplus_id = login_session.get('gplus_id')
	if stored_credentials is not None and gplus_id == stored_gplus_id :
		response = make_response(json.dumps("Current user is already connected"), 200)
		response.headers['Content-Type'] = 'application/json'

	#store access token
	login_session['credentials'] = credentials
	login_session['gplus_id'] = gplus_id

	#get user info
	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = { 'access_token': credentials.access_token, 'alt': 'json'}

	answer = requests.get(userinfo_url, params = params)
	data = json.loads(answer.text)

	login_session['email'] = data['email']
	login_session['username'] = data['name']
	login_session['picture'] = data['picture']
	login_session['provider'] = 'google'

	#check if the user exists
	user_id = getUserID(data['email'])

	if not user_id :
		user_id = createUser(login_session)

	login_session['user_id'] = user_id

	'''check if there is an active access token to set to the user '''
	token = get_access_token(user_id)

	if token is None :
		token = create_access_token(user_id)

	login_session['access_token'] = token.token

	flash('You are now logged in as ' + login_session['username'])
	response = make_response(json.dumps(True), 200)
	response.headers['Content-Type'] = 'application/json'
	return response


'''handle disconnecting from all services'''
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        del login_session['access_token']
        flash("You have successfully been logged out.")
        return redirect('/')
    else:
        flash("You were not logged in")
        return redirect('/')

'''handle google disconnect'''
@app.route('/gdisconnect')
def gdisconnect():
   	# Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

'''handle facebook disconnect'''
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


if __name__ == '__main__':
	"""first seed the test data """
	seeder.populate()

	app.debug = False
	app.secret_key = 'super secret key'
	app.run(host='0.0.0.0', threaded = True)