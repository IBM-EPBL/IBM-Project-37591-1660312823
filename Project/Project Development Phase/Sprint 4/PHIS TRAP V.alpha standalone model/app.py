import flask
from flask import Flask, render_template, request, redirect
import joblib
import inputScript
import regex
import sys
import logging
from forms import ContactForm
from flask_mail import Message, Mail

mail = Mail()

app = Flask(__name__)
app.secret_key = '670a9a54ac0304f8ad16324a'

app.config['MAIL_SERVER']='smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = '5cd9be5c01dfef'
app.config['MAIL_PASSWORD'] = '52d662bc320489'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail.init_app(app)

app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.ERROR)


@app.route('/')
@app.route('/index')
def index():
    return flask.render_template('home.html')

@app.route('/about')
def about():
    return flask.render_template('about.html')

@app.route('/predict', methods = ['POST'])
def make_prediction():
    LogisticRegression = joblib.load(r'D:\college\Nalaya thiran\PHIS TRAP v.alpha\model\Phishing_website.pkl', 'rb')
    if request.method=='POST':
        url = request.form['url']
        if not url:
            return render_template('home.html', label = 'Please input url')
        elif(not(regex.search(r'^(http|ftp)s?://', url))):
            return render_template('home.html', label = 'Please input full url, for exp- https://facebook.com')
        
        
        checkprediction = inputScript.main(url)
        prediction = LogisticRegression.predict(checkprediction)

        if prediction[0]==1 :
            label = 'website is not legitimate'
        elif prediction[0]==-1:
            label ='website is legitimate'
        
        return render_template('home.html', label=label)
    
@app.route('/contact', methods=['GET', 'POST'])
def contact():
  form = ContactForm()
 
  if request.method == 'POST':
    if form.validate() == False:
      flash('All fields are required.')
      return render_template('contact.html', form=form)
    else:
      msg = Message(form.subject.data, sender='contact@example.com', recipients=['your_email@example.com'])
      msg.body = """
      From: %s &lt;%s&gt;
      %s
      """ % (form.name.data, form.email.data, form.message.data)
      mail.send(msg)
 
      return redirect("/index")
 
  elif request.method == 'GET':
    return render_template('contact.html', form=form)
        
        
if __name__ == '__main__':
    LogisticRegression = joblib.load(r'D:\college\Nalaya thiran\PHIS TRAP v.alpha\model\Phishing_website.pkl', 'rb')
    app.run()
























#designed by NAVRSAM