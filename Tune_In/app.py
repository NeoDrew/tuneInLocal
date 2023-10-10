'''
    Main app for running the webpage.
        -Control of webpages
        -Controls user info transmission between client and database, spotify.
'''
from flask import *
import tekore as tk
import mysql.connector as sr
import bcrypt as bc
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = ""
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

try:
    conn = sr.connect(host='localhost', user='root', database='tunein')
except:
    try:
        conn = sr.connect(host='localhost', user='root',
                          password="root", database='tunein')
    except:
        conn = sr.connect(host='localhost', user='root',
                          database='tunein', password='rootroot')

# conn = sr.connect(host='localhost', user='root', database='tunein')
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'tunein'
# mysql=MySQL(app)

client_id = "93f90e1938c1427c8081f41ef3508828"
client_secret = "1a03ad753ab8475db5efc1a052c2a104"
app_token = tk.request_client_token(client_id, client_secret)
auths = {}
spotify = tk.Spotify(app_token)


'''Main Pages'''
# Need to check database for current user if they have submitted a song.


# Defualt app route, use for main homepage. e.g. "tunein.com/"
@app.route("/", methods=['GET', 'POST'])
def home():
    if (not (session.get('triedLoggingIn'))):
        session['loggedIn'] = False
        session['submittedSong'] = False
        session['username'] = ""
        session['email'] = ""
        session['token'] = None
        session['friends'] = []
        session['spotifyUsername'] = ""
        session['followers'] = []
    # cur = mysql.connection.cursor()
    # cur.execute("CREATE DATABASE TEST2") #testimg if connection has been established
    # mysql.connection.commit()
    cur = conn.cursor()
    cur.execute("CREATE database IF NOT EXISTS tunein")
    cur.execute("USE tunein")
    # cur.execute('Create database TEST2')
    # tquery = "Create table userlogin(username varchar(32),password varchar(128),email id varchar(128));"
    # cur.execute("Drop table if exists userlogin")
    cur.execute("Create table IF NOT EXISTS userlogin(username varchar(32),password varchar(128),email_id varchar(128),access_token varchar(520),response_token varchar(520))")
    cur.execute(
        "Create table IF NOT EXISTS songinput(username varchar(32),song_added varchar(120),song_liked varchar(120))")
    cur.execute(
        "Create table IF NOT EXISTS friends(username varchar(32),username_friend varchar(32))")
    cur.execute(
        "Create table IF NOT EXISTS friend_request(username varchar(32),username_friendreq varchar(32))")
    # add a new column named added_at to your songinput table with a default value of the current timestamp.
    try:
        cur.execute(
            "ALTER TABLE songinput ADD COLUMN added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;")
    except:
        pass

    try:
        cur.execute(
            "Alter table userlogin add column submit_song boolean not null default 0")
    except:
        pass

    # cur.execute("ALTER TABLE userlogin ADD COLUMN IF NOT EXISTS access_token VARCHAR(520)")
    # cur.execute("ALTER table userlogin ADD COLUMN IF NOT EXISTS response_token varchar (520)")
    if not (session.get('loggedIn')):
        return redirect(url_for('login'))
    query_checkflag = "Select submit_song from userlogin where username = %s"
    data_checkflag = (session.get('username'),)
    cur.execute(query_checkflag, data_checkflag)

    session['submit_song_flag'] = cur.fetchone()[0]
    if (session.get('submit_song_flag')):
        return render_template('home.html')
    elif session['token'] == None:
        if request.method == "POST":  # if connect spotify button pressed
            return redirect(url_for('spotify_authenticate'))
        return render_template("connect_spotify.html")
    else:
        track = fetch_most_recent_track(session.get('token'))
        if track == None:
            return render_template('song_error.html', username=session.get('username'))
        trackid = track.id
        session['trackid'] = trackid
        if request.method == "POST":  # if submit song button pressed?
            # database function to insert song here (use trackid)
            pass
        if (session.get('submit_song_flag') == False):
            return render_template('home2.html', username=session.get('username'), src=trackid)
        return render_template('home.html', username=session.get('username'), src=trackid)


@app.route("/feed", methods=['GET', 'POST'])
def feed():
    if not (session.get('loggedIn')):
        return redirect(url_for('login'))
    if not (session.get('token')):
        return redirect(url_for('home'))
    if request.method == "POST":
        pass  # Save the request.form[]
    else:
        pass  # render songs
        friends_id = []
        if session.get('friends') != None:
            for friend in session.get('friends'):
                query_getid = "Select song_added from songinput where username = %s"
                data_getid = (friend[0],)
                cur = conn.cursor(buffered=True)
                cur.execute(query_getid, data_getid)
                friendIDFromDB = cur.fetchall()
                if len(friendIDFromDB) != 0:
                    friends_id.append([friend[0], friendIDFromDB[-1][0]])

        # retrieve the most recently added song ID based on the added_at column.
        query_getid = "SELECT song_added FROM songinput WHERE username = %s ORDER BY added_at DESC LIMIT 1"
        data_getid = (session.get('username'),)
        cur = conn.cursor(buffered=True)
        cur.execute(query_getid, data_getid)
        idFromDB = cur.fetchone()[0]

    return render_template('feed.html', uri_day=idFromDB, friends_id=friends_id)


@app.route("/my_tunes")
def myTunes():
    if not (session.get('loggedIn')):
        return redirect(url_for('login'))
    if not (session.get('token')):
        return redirect(url_for('home'))
    cur = conn.cursor()
    query_getsongs = "Select song_added from songinput where username=%s"
    data_getsongs = (session.get('username'),)
    cur.execute(query_getsongs, data_getsongs)
    song_list = cur.fetchall()
    conn.commit()
    songlist = []
    for tuples in song_list:
        songlist.append(tuples[0])


    return render_template('my_tunes.html', usersonglist=songlist)


@app.route("/whatspopular")
def popular():
    if not (session.get('loggedIn')):
        return redirect(url_for('login'))
    if not (session.get('token')):
        return redirect(url_for('home'))
    return render_template('whats_popular.html')


'''Friends'''


@app.route("/myfriends", methods=['GET', 'POST'])
def friends():
    if not (session.get('loggedIn')):
        return redirect(url_for('login'))
    if not (session.get('token')):
        return redirect(url_for('home'))
    cur = conn.cursor()
    query_useid = "Select username_friend from friends where username = %s "
    data_usernameAndSearch = (session.get('username'),)
    cur.execute(query_useid, data_usernameAndSearch)
    new_friendlist = cur.fetchall()
    session['friends'] = new_friendlist
    conn.commit()
    cur = conn.cursor()
    query_useid = "Select username from friends where username_friend = %s "
    data_usernameAndSearch = (session.get('username'),)
    cur.execute(query_useid, data_usernameAndSearch)
    session['followers'] = cur.fetchall()
    conn.commit()
    # friendlist = cur.fetchall()
    followinglist = []
    for tuples in session.get('friends'):
        followinglist.append(tuples[0])
    followerslist = []
    for tuples1 in session.get('followers'):
        followerslist.append(tuples1[0])
    return render_template('my_friends.html', following=followinglist, followers=followerslist)


@app.route("/search_for_followers")
def followersSearch():
    if not (session.get('loggedIn')):
        return redirect(url_for('login'))
    if not (session.get('token')):
        return redirect(url_for('home'))
    return render_template('Follow_more.html', searchUsername='Username')


@app.route("/searchUsers", methods=['POST'])
def searchUsers():
    # following
    if not (session.get('loggedIn')):
        return redirect(url_for('login'))
    if not (session.get('token')):
        return redirect(url_for('home'))
    userToSearch = request.form['userToSearch']

    # Check if username is our own
    if (userToSearch == session.get('username')):
        return render_template("Follow_more.html", searchUsername='Username', Username=None, userSearched=True, searchError="Error: you cannot follow yourself")

    # Check to see if the user exists
    cur = conn.cursor()
    query_useid = "Select username from userlogin where username = %s"
    data_userToSearch = (userToSearch,)
    cur.execute(query_useid, data_userToSearch)
    usernameFromDb = cur.fetchone()

    if not (usernameFromDb):
        return render_template("Follow_more.html", searchUsername='Username', Username=None, userSearched=True, searchError="Error: Account not found")

    # If they do exist, but we are already following.
    cur = conn.cursor()
    query_useid = "Select username_friend from friends where username = %s "
    data_usernameAndSearch = (session.get('username'),)
    cur.execute(query_useid, data_usernameAndSearch)
    new_friendlist = cur.fetchall()
    print(new_friendlist)
    for i in range(len(new_friendlist)):
        if userToSearch in new_friendlist[i][0]:
            print("1 - "+ userToSearch)
            session['TheError'] = 'this'
            session['userTofollow'] = userToSearch
            print("1.5 - "+ session.get('userTofollow'))
            return render_template("Follow_more.html", searchUsername = userToSearch, Username=userToSearch, userSearched=True, following=True)
        
    # Else, they are valid to display
    session['userToFollow'] = request.form['userToSearch']
    print("2 - "+ userToSearch)
    return render_template("Follow_more.html", searchUsername = userToSearch, Username=userToSearch, userSearched=True, following=False)


@app.route("/followUser", methods=['POST'])
def followUser():
    if not (session.get('loggedIn')):
        return redirect(url_for('login'))
    if not (session.get('token')):
        return redirect(url_for('home'))

    userToAdd = session.get('userToFollow')
    print("3 - "+ userToAdd)
    cur = conn.cursor()
    query_addFriend = "insert into friends(username,username_friend) values(%s,%s)"
    data_friendinput = (session.get('username'), userToAdd)
    cur.execute(query_addFriend, data_friendinput)
    conn.commit()
    

    return render_template("Follow_more.html", searchUsername = userToAdd, Username=userToAdd, userSearched=True, following=True)


@app.route("/unFollowUser", methods=['POST'])
def unFollowUser():
    if not (session.get('loggedIn')):
        return redirect(url_for('login'))
    if not (session.get('token')):
        return redirect(url_for('home'))

    userToUnadd = session.get('userToFollow')
    print("4 - "+ userToUnadd)
    print(session.get('TheError'))
    cur = conn.cursor()
    query = "DELETE FROM friends WHERE username = %s AND username_friend = %s"
    data = (session.get('username'), userToUnadd)
    cur.execute(query, data)
    conn.commit()

    return render_template("Follow_more.html", searchUsername = userToUnadd, Username=userToUnadd, userSearched=True, following=False)


'''Settings'''


@app.route("/usersettings", methods=['GET', 'POST'])
def userSettings():
    if not (session.get('loggedIn')):
        return redirect(url_for('login'))
    # if not (userSesh.token): return redirect(url_for('home'))

    try:
        token = tk.refresh_user_token(
            client_id, client_secret, session.get("token"))
        with spotify.token_as(token):
            session['spotifyUsername'] = spotify.current_user().display_name
    except:
        return render_template('my_account.html', username=session.get('username'), email=session.get('email'), spotify_username='(Unconnected)')

    return render_template('my_account.html', username=session.get('username'), email=session.get('email'), spotify_username=session.get('spotifyUsername'))


@app.route("/submitNewUsername", methods=['POST'])
def handleNameChange():
    cur = conn.cursor()
    new_username = request.form['newUsernameIn']
    if (new_username == session.get('username')):
        return render_template('my_account.html', username=session.get('username'), email=session.get('email'), spotify_username=session.get('spotifyUsername'), Error="Username must be different.")
    # Checking if the username was taken.
    query_useid = "Select username from userlogin where username = %s"
    data = (new_username,)
    cur.execute(query_useid, data)
    usernameFromDb = cur.fetchone()
    if (usernameFromDb):
        return render_template('my_account.html', username=session.get('username'), email=session.get('email'), spotify_username=session.get('spotifyUsername'), Error="Username already taken.")
    # save username to database
    cur = conn.cursor()
    changeusername_query = "UPDATE userlogin SET username = %s where username = %s"
    data = (new_username, session['username'])
    cur.execute(changeusername_query, data)
    conn.commit()

    session['username'] = new_username
    return render_template('my_account.html', username=session.get('username'), email=session.get('email'), spotify_username=session.get('spotifyUsername'), Error="Success.")


@app.route("/submitNewPassword", methods=['POST'])
def handlePasswordChange():
    newPassword = setPassword(request.form['newPasswordIn'])
    # save password to database
    cur = conn.cursor()
    changepasswd_query = "UPDATE userlogin SET password = %s where username = %s"
    data = (newPassword, session.get("username"))
    cur.execute(changepasswd_query, data)
    conn.commit()

    return render_template('my_account.html', username=session.get("username"), email=session.get("email"), spotify_username=session.get("spotifyUsername"))


@app.route("/reconfirm_del", methods=['GET', 'POST'])
def delete_page():
    if not (session["loggedIn"]):
        return redirect(url_for('login'))
    # if not (userSesh.token): return redirect(url_for('home'))

    token = tk.refresh_user_token(
        client_id, client_secret, session.get("token"))
    with spotify.token_as(token):
        session["spotifyUsername"] = spotify.current_user().display_name

    return render_template('delete_account.html')


@app.route("/no_deletetion", methods=['POST', "GET"])
def nvm_delete():
    if not (session["loggedIn"]):
        return redirect(url_for('login'))
    # if not (userSesh.token): return redirect(url_for('home'))

    token = tk.refresh_user_token(
        client_id, client_secret, session.get("token"))

    with spotify.token_as(token):
        session["spotifyUsername"] = spotify.current_user().display_name

    return redirect(url_for('userSettings'))


@app.route("/submit_song")
def submit_song():
    cur = conn.cursor()
    query_songflag = "UPDATE userlogin set submit_song = 1 where username = %s"
    data_songflag = (session.get("username"),)
    cur.execute(query_songflag, data_songflag)
    query_insertsong = "insert into songinput(username,song_added) values(%s,%s)"
    data_songinput = (session.get("username"), session.get('trackid'))
    cur.execute(query_insertsong, data_songinput)
    conn.commit()
    return redirect(url_for("home"))


# for clock function
@app.route('/update-song-submission-status', methods=['POST', 'GET'])
def update_song_sub_status():
    cur = conn.cursor()
    query_songflag = "UPDATE userlogin set submit_song = 0 where username = %s"
    data_songflag = (session.get("username"),)
    cur.execute(query_songflag, data_songflag)
    conn.commit()
    return redirect(url_for("home"))


@app.route("/delAccount", methods=['POST'])
def handleDeleteAcc():
    cur = conn.cursor()
    data = (session.get("username"), )
    query = "delete from userlogin where username = %s"
    cur.execute(query, data)
    conn.commit()
    cur = conn.cursor()
    data = (session.get("username"), )
    query = "delete from songinput where username = %s"
    cur.execute(query, data)
    conn.commit()
    cur = conn.cursor()
    data = (session.get("username"), )
    query = "delete from friends where username = %s"
    cur.execute(query, data)
    conn.commit()
    clearSesh()

    return redirect(url_for('login'))


@app.route("/logout", methods=['POST', 'GET'])
def log_out():
    clearSesh()
    return redirect(url_for('login'))


'''Login/Registration'''


@app.route('/register', methods=['GET', 'POST'])  # First page user sees
def register():
    cur = conn.cursor()
    registerError = None
    if request.method == "POST":  # When user presses 'login'
        '''From here, check if the username and email were used already
            aka, get them from database and compare.'''

        email = request.form['email']
        password = setPassword(request.form['password'])
        username = request.form['username']

        query_useid = "Select username from userlogin where username = %s"
        data = (username,)
        cur.execute(query_useid, data)
        usernameFromDb = cur.fetchone()

        query_useid = "Select email_id from userlogin where email_id = %s"
        data = (email,)
        cur.execute(query_useid, data)
        emailFromDb = cur.fetchone()

        if (not (usernameFromDb or emailFromDb)):
            session["loggedIn"] = True
            data = (username, password, email)
            query = "insert into userlogin(username,password,email_id) values(%s,%s,%s)"
            cur.execute(query, data)
            conn.commit()
            session["username"] = username
            session["email"] = email
            return redirect(url_for('spotify_authenticate'))
        else:
            registerError = 'Username or email already in use.'
            return render_template('register.html', registerErrorIn=registerError)
    return render_template('register.html', registerErrorIn=registerError)


@app.route('/login', methods=['GET', 'POST'])  # Defualt page on user start.
def login():
    loginError = None
    session['triedLoggingIn'] = True
    redirect_url = url_for(endpoint='spotify_get_access_token', _external=True)
    cred = tk.Credentials(client_id, client_secret, redirect_url)
    if request.method == "POST":  # When user presses 'login'
        '''Here, we send the input email to database and retrieve relative password'''

        email = request.form['email']
        password = request.form['password']
        cur = conn.cursor()
        # data = (password,email)
        # query = "insert into userlogin(password,email_id) values(%s,%s)"
        # cur.execute(query,data)

        '''Get password from database and use checkPassword(rawPW, hashedPW)'''
        query = "Select password from userlogin where email_id = %s"
        data = (email,)
        cur.execute(query, data)
        result = cur.fetchone()
        if result:
            result = result[0]
        else:
            loginError = 'Account does not exist'
            return render_template('login_returning.html', loginError=loginError)

        # If their password matched with their email. .encode('utf-8')
        if (checkPassword(password, result)):
            session["loggedIn"] = True
            query = "Select username, response_token from userlogin where email_id = %s"
            data = (email,)
            cur.execute(query, data)
            username, refresh_token = cur.fetchall()[0]
            session["username"] = username
            session["email"] = email

            if refresh_token == None:
                session["token"] = None
            else:
                session["token"] = refresh_token

        #    userSesh.token = 'k' #for debugging page

            # get friends
            # query = "SELECT username_friend FROM friends WHERE username = %s"
            # data = (userSesh.username,)
            # cur.execute(query, data)
            # userSesh.friends = cur.fetchall()[0]

            cur = conn.cursor()
            query_useid = "Select username_friend from friends where username = %s "
            data_usernameAndSearch = (session.get("username"),)
            cur.execute(query_useid, data_usernameAndSearch)
            friendlist = cur.fetchall()
            session["friends"] = friendlist

            cur = conn.cursor()
            query_useid = "Select username from friends where username_friend = %s "
            data_usernameAndSearch = (session["username"],)
            cur.execute(query_useid, data_usernameAndSearch)
            session["followers"] = cur.fetchall()
            conn.commit()

            cur = conn.cursor()
            query_checkifsongadded = "Select song_added from songinput where username = %s"
            data_checkifsongadded = (session.get('username'),)
            cur.execute(query_checkifsongadded, data_checkifsongadded)
            result = cur.fetchall()
            if len(result) == 0:
                pass
            elif len(result) != 0:
                session['submittedSong'] = True

            return redirect(url_for('home'))
        else:  # Else user failed to login
            loginError = 'Invalid Credentials. Please try again.'

    # cur = conn.cursor()
    # query_useid = "Select username_friend from friends where username = %s "
    # data_usernameAndSearch = (userSesh.username,)
    # cur.execute(query_useid, data_usernameAndSearch)
    # friendlist = cur.fetchall()
    # userSesh.friends = friendlist

    # cur = conn.cursor()
    # query_useid = "Select username from friends where username_friend = %s "
    # data_usernameAndSearch = (userSesh.username,)
    # cur.execute(query_useid, data_usernameAndSearch)
    # userSesh.followers = cur.fetchall()
    # conn.commit()

    return render_template('login_returning.html', loginError=loginError)


'''Spotify'''


# spotify authentication page, e.g. "tunein.com/spotify"
@app.route("/spotify")
def spotify_authenticate():
    """initialises spotify authentication process"""
    redirect_url = url_for(endpoint='spotify_get_access_token', _external=True)
    cred = tk.Credentials(client_id, client_secret, redirect_url)
    scope = tk.Scope(tk.scope.user_read_recently_played,
                     tk.scope.user_read_playback_state)
    auth = tk.UserAuth(cred, scope)  # sets up user spotify authentication
    # stores the authentication object in a dictionary
    auths[auth.state] = auth
    return redirect(auth.url)  # redirects user


# redirect for spotify authentication e.g. "tunein.com/redirect"
@app.route("/redirect", methods=["GET"])
def spotify_get_access_token():
    """obtains access token"""
    code = request.args.get("code", None)
    state = request.args.get("state", None)
    auth = auths.pop(state, None)
    token = auth.request_token(code, state)

    cur = conn.cursor()
    query = "UPDATE userlogin SET response_token = %s WHERE username=%s"
    data = (token.refresh_token, session.get("username"))
    session["token"] = token.refresh_token
    cur.execute(query, data)
    conn.commit()

    return redirect(url_for("home"))


'''Information Pages'''


@app.route("/about")
def about():
    if not (session.get("loggedIn")):
        return redirect(url_for('login'))
    if not (session.get("token")):
        return redirect(url_for('home'))
    return render_template('about_us.html')


@app.route("/contact-us")
def contactUs():
    if not (session.get("loggedIn")):
        return redirect(url_for('login'))
    if not (session.get("token")):
        return redirect(url_for('home'))
    return render_template('contact_us.html')


@app.route("/TCs")
def TCs():
    if not (session.get("loggedIn")):
        return redirect(url_for('login'))
    if not (session.get("token")):
        return redirect(url_for('home'))
    return render_template('terms_and_conditions.html')


'''Misc'''


def setPassword(plain_text_password):
    # Hash a password for the first time
    #   (Using bcrypt, the salt is saved into the hash itself)
    return bc.hashpw(plain_text_password.encode('utf-8'), bc.gensalt())


def checkPassword(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bc.checkpw(plain_text_password.encode('utf-8'), hashed_password.encode('utf-8'))


def fetch_most_recent_track(token):
    """takes a token object and returns the most recently played/currently playing track
    for the user corresponding to that token"""
    token = tk.refresh_user_token(
        client_id, client_secret, session.get("token"))
    with spotify.token_as(token):
        playback = spotify.playback(tracks_only=True)
        recently_played = spotify.playback_recently_played(limit=50)
    if playback != None and playback.currently_playing_type == "track":
        # fetch currently played track if something is being played
        return playback.item
    elif len(recently_played.items) != 0:
        # otherwise find their most recently played track
        return recently_played.items[0].track
    else:
        return None


def clearSesh():
    session['loggedIn'] = False
    session['submittedSong'] = False
    session['username'] = ""
    session['email'] = ""
    session['token'] = None
    session['friends'] = []
    session['spotifyUsername'] = ""
    session['followers'] = None
# UserSession Used to be here, here lies the grave of usersesh...


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
