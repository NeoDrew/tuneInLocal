''' Initial test for flask.
    Enter any information here:

    *Referencing this video for learning: 
        https://www.youtube.com/watch?v=mqhxxeeTbu0&ab_channel=TechWithTim
        https://www.youtube.com/watch?v=9MHYHgh4jYc&ab_channel=TechWithTim

    *Flask will ouput a link to console, 
        to run the webpage, ctrl+click the link.

    *This file acts as a test for the Flask framework
        this isn't intended to be used for the project
        but can be referenced when we start.
'''
from flask import Flask, redirect, url_for, render_template

app = Flask(__name__)

@app.route("/")
def home():
    return render_template('home.html')

@app.route("/<name>") 
def user(name):
    return f"Hello {name}!"

@app.route("/admin")    #If the user tries to access /admin webpage
def admin():            #they will be returned to "home" 
    return redirect(url_for("home")) 

if __name__ == "__main__":
    app.run()