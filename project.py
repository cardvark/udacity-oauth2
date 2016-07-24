from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from flask import session as login_session
import random
import string
app = Flask(__name__)

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

import database_setup

# creates flow object from client secrets json file
# (which has client id, client secret, other oauth2 parameters.)
from oauth2client.client import flow_from_clientsecrets

# if run into error trying to exchange auth code for access token
# this will catch.
from oauth2client.client import FlowExchangeError
import httplib2
import json

# converts return value from a function
# to a response object we can send to client.
from flask import make_response
import requests


#Connect to Database and create database session
engine = database_setup.engine
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# client ID
# 202542788499-64qmr7agdj74vu8ck4qvqapupoto4jp9.apps.googleusercontent.com
# client secret
# xQ4g1gEeRCuxtQDrg5GEdQH3


# client_secrets.json downloaded from credentials page:
# https://console.developers.google.com/apis/credentials?project=swift-adviser-137423
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = 'Restaurant Menu Application'


# User helper functions

def createUser(login_session):
    new_user = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture']
        )
    session.add(new_user)
    session.commit()
    return new_user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    # Verify value of 'state' to protect against cross-site reference
    # forgery attacks.
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = request.data
    print 'access token received {token}'.format(token=access_token)

    # Exchange client token for long-lived server side token w/ GET token_url

    fb_client_json = open('fb_client_secrets.json', 'r').read()

    app_id = json.loads(fb_client_json)['web']['app_id']
    app_secret = json.loads(fb_client_json)['web']['app_secret']
    token_url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id={id}&client_secret={secret}&fb_exchange_token={token}'.format(
        id=app_id,
        secret=app_secret,  # verifies server identity
        token=access_token  # the short lived token
        )
    h = httplib2.Http()
    result = h.request(token_url, 'GET')[1]  # the long lived token

    # Use token to get user info from API
    base_url = 'https://graph.facebook.com/v2.4/me'
    # print 'Raw token: ' + result
    # Example raw token:
    # access_token=EAAJ9ftJwZBGsBANry54sZCGxcVZBTkJQ40FUgODw3SqopdZASNIEOxvkoZChLWRS81p4AG9GjZC8KZA7q6zRaZCbfuRcTwJmUpVZAmekY4qj3YU47DV2L6k1VOTZCz0aJdWow3FjUELL8V2i166qoJRtKSM5IjjjFwYlAZD&expires=5184000

    # Strip expire tag from access token
    # Don't need expiration tag for API calls.
    token = result.split('&')[0]

    userinfo_url = base_url + '?{token}&fields=name,id,email'.format(token=token)
    h = httplib2.Http()
    user_result = h.request(userinfo_url, 'GET')[1]

    user_data = json.loads(user_result)
    login_session['provider'] = 'facebook'
    login_session['username'] = user_data['name']
    login_session['email'] = user_data['email']
    login_session['facebook_id'] = user_data['id']

    # Token must be stored in login_session in order to properly logout.
    # Strip out info before '=' in our token
    stored_token = token.split('=')[1]
    login_session['access_token'] = stored_token

    # Get user pic
    pic_url = base_url + '/picture?{token}&redirect=0&height=200&width=200'.format(token=token)
    h = httplib2.Http()
    pic_result = h.request(pic_url, 'GET')[1]
    pic_data = json.loads(pic_result)

    login_session['picture'] = pic_data['data']['url']

    # See if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash('Now logged in as {name}'.format(name=login_session['username']))
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']

    # access token must be included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/{id}/permissions?access_token={token}'.format(
        id=facebook_id,
        token=access_token
        )
    h = httplib2.Http()
    result = json.loads(h.request(url, 'DELETE')[1])

    return 'You have been logged out'

    # print 'result is '
    # print result

    # if result.get('success') is True:
    #     del login_session['user_id']
    #     del login_session['access_token']
    #     del login_session['facebook_id']
    #     del login_session['username']
    #     del login_session['email']
    #     del login_session['picture']
    #     del login_session['provider']
    #     response = make_response(json.dumps('Successfully disconnected.'), 200)
    #     response.headers['Content-Type'] = 'application/json'
    #     return response
    # else:
    #     response = make_response(json.dumps('Failed to revoke token for given user.'), 400)
    #     response.headers['Content-Type'] = 'application/json'
    #     return response


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # checks that token clients sends to the server
    # matches the token server sent to client.
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalud state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # if no problem, proceed.
    # retrieves one-time-code from server w/ request.data function
    code = request.data
    try:
        # Upgrade authorization code into a credentials object.

        # creates oauth flow object, attached json secrets.
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')

        # specify with 'postmessage' that this is the one-time-code flow
        # the server will be sending off.
        oauth_flow.redirect_uri = 'postmessage'

        # initiate exchange, passing in one-time-code as input.
        # exchanges for credentials.
        credentials = oauth_flow.step2_exchange(code)

    # if there's an error:
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token

    # google api server can verify if token is valid.
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={token}'.format(token=access_token))
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # if any errors, send 500 internal server error to client
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # else, have a working access token.
    # Verify that access token is used for intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps('Token\'s user ID doesn\'t match given user ID.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps('Token\'s client ID does not match app\'s.'), 401)
        print 'Token\'s client ID does not match app\'s.'
        response.headers['Content-Type'] = 'application/json'
        return response

    # Chek if user is already logged in.
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # if none of the above triggered:
    # store access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # Obtains user.id from email, or adds user to DB and gets ID.
    user_id = getUserID(login_session['email'])

    if user_id is None:
        user_id = createUser(login_session)

    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash('You are now logged in as {name}'.format(name=login_session['username']))
    print 'done!'
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    print 'In gdisconnect, access token is {token}'.format(token=access_token)
    print 'User name is: '
    print login_session.get('username')

    if access_token is None:
        print 'Access token is None'
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    url = 'https://accounts.google.com/o/oauth2/revoke?token={token}'.format(token=access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] != '200':
        response = make_response(json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    # print 'result is '
    # print result

    # if result['status'] == '200':
    #     del login_session['user_id']
    #     del login_session['access_token']
    #     del login_session['gplus_id']
    #     del login_session['username']
    #     del login_session['email']
    #     del login_session['picture']
    #     del login_session['provider']
    #     response = make_response(json.dumps('Successfully disconnected.'), 200)
    #     response.headers['Content-Type'] = 'application/json'
    #     return response
    # else:
    #     response = make_response(json.dumps('Failed to revoke token for given user.'), 400)
    #     response.headers['Content-Type'] = 'application/json'
    #     return response


# Universal
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['user_id']
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['provider']

        flash('You have been successfully logged out.')
    else:
        flash('You were not logged in.')

    return redirect(url_for('showRestaurants'))


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state

    return render_template('login.html', STATE=state)

    """
    Placed within <head> tags
    <script src="https://apis.google.com/js/client:platform.js?onload=start" async defer></script>

    Creates anonymous function that inserts script into the dom of login.html page.

    """

    """
    note - placed inside the <span> tag for google signin button.

    <span class="g-signin"
    data-scope="openid"
        # specifies what google resources we want to access.
        # 'openid' - user's name, profile pic, email address.
    data-clientid="202542788499-64qmr7agdj74vu8ck4qvqapupoto4jp9.apps.googleusercontent.com"
        # generated when registrating web app
    data-redirecturi="postmessage"
        # sets a postmessage, enables one time use code flow.
    data-accesstype="offline"
        # means server can make request to google API server even if user not logged in
    data-cookiepolicy="single_host_origin"
        # determines scope of URIs that can access cookie.
        # 'single_host_origin' if page has single host and no sub-domains.
    data-callback="signInCallback"
        # specifies callback function
        # if user clicks and gives authorization to use profile,
        # this callback method is called, given one time use code and access token.
    data-approvalprompt="force"
        # user has to login each time they visit the login page. doesn't check if already logged in.
        # good for debugging, bad for users so want to disable later.
    >

    """


#JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])


#Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))

    if 'username' not in login_session:
        return render_template('publicrestaurants.html', restaurants=restaurants)
    return render_template('restaurants.html', restaurants=restaurants)


#Create a new restaurant
@app.route(
    '/restaurant/new/',
    methods=['GET', 'POST']
    )
def newRestaurant():
    # create and delete login_session['username'] with each log in / oeut
    # so this should a safe way to check against whether a user is logged in.
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        newRestaurant = Restaurant(
            name=request.form['name'],
            user_id=login_session['user_id']
            )
        session.add(newRestaurant)
        flash('New Restaurant %s Successfully Created' % newRestaurant.name)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('newRestaurant.html')


#Edit a restaurant
@app.route(
    '/restaurant/<int:restaurant_id>/edit/',
    methods=['GET', 'POST']
    )
def editRestaurant(restaurant_id):
    editedRestaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if 'username' not in login_session:
        return redirect('/login')

    if login_session.get('user_id') != editedRestaurant.user_id:
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))

    if request.method == 'POST':
        if request.form['name']:
            editedRestaurant.name = request.form['name']
            flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
            return redirect(url_for('showRestaurants'))
    else:
        return render_template('editRestaurant.html', restaurant=editedRestaurant)


#Delete a restaurant
@app.route(
    '/restaurant/<int:restaurant_id>/delete/',
    methods=['GET', 'POST']
    )
def deleteRestaurant(restaurant_id):
    restaurantToDelete = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if 'username' not in login_session:
        return redirect('/login')

    if login_session.get('user_id') != restaurantToDelete.user_id:
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))

    if request.method == 'POST':
        session.delete(restaurantToDelete)
        flash('%s Successfully Deleted' % restaurantToDelete.name)
        session.commit()
        return redirect(url_for('showRestaurants', restaurant_id=restaurant_id))
    else:
        return render_template('deleteRestaurant.html', restaurant=restaurantToDelete)


#Show a restaurant menu
@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
    creator = getUserInfo(restaurant.user_id)

    if login_session.get('user_id') == restaurant.user_id:
        return render_template(
            'menu.html',
            items=items,
            restaurant=restaurant,
            creator=creator
            )
    else:
        return render_template(
            'publicmenu.html',
            items=items,
            restaurant=restaurant,
            creator=creator
            )


#Create a new menu item
@app.route(
    '/restaurant/<int:restaurant_id>/menu/new/',
    methods=['GET', 'POST']
    )
def newMenuItem(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if 'username' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        newItem = MenuItem(
            name=request.form['name'],
            description=request.form['description'],
            price=request.form['price'],
            course=request.form['course'],
            restaurant_id=restaurant_id,
            user_id=login_session['user_id']
        )
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id=restaurant_id)


#Edit a menu item
@app.route(
    '/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit',
    methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if 'username' not in login_session:
        return redirect('/login')

    if login_session.get('user_id') != editedItem.user_id:
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))

    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template(
            'editmenuitem.html',
            restaurant_id=restaurant_id,
            menu_id=menu_id,
            item=editedItem
            )


#Delete a menu item
@app.route(
    '/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete',
    methods=['GET', 'POST']
    )
def deleteMenuItem(restaurant_id, menu_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if 'username' not in login_session:
        return redirect('/login')

    if login_session.get('user_id') != itemToDelete.user_id:
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))

    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item=itemToDelete)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
