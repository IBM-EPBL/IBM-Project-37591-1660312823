import flask
from flask import Flask, render_template, request, redirect, jsonify
import joblib
import regex
import sys
import requests
import json
import inputScript
import logging
from forms import ContactForm
from flask_mail import Message, Mail

API_KEY = "9fwquUvd1daYqNf6N0f-0viRwLOjDb-__xY73VKnoT2Q"
token_response = requests.post('https://iam.cloud.ibm.com/identity/token', data={"apikey":API_KEY, "grant_type": 'urn:ibm:params:oauth:grant-type:apikey'})
mltoken = token_response.json()["access_token"]

header = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + mltoken}
    

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
    url = request.form['url']
    checkprediction = inputScript.main(url)
    payload_scoring = {"input_data": [{"field": [["having_IPhaving_IP_Address","URLURL_Length","Shortining_Service","having_At_Symbol","double_slash_redirecting",
        "Prefix_Suffix","having_Sub_Domain","SSLfinal_State","Domain_registeration_length","Favicon","port",
        "HTTPS_token","Request_URL","URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email",
        "Abnormal_URL","Redirect","on_mouseover","RightClick",
        "popUpWidnow","Iframe","age_of_domain","DNSRecord","web_traffic	Page_Rank","Google_Index","Links_pointing_to_page","Statistical_report"
    ]], "values": checkprediction }]}
    response_scoring = requests.post('https://us-south.ml.cloud.ibm.com/ml/v4/deployments/01674dac-1f17-4b13-bb68-3bf84840f4d0/predictions?version=2022-11-09', json=payload_scoring,
    headers={'Authorization': 'Bearer ' + mltoken})
    print(response_scoring)
    pred = response_scoring.json()
    print(pred)
    prediction = pred['predictions'][0]['values'][0][0]
    print(prediction)
    if prediction==1 :
            label = 'website is not legitimate'
    elif prediction==-1:
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
      msg = Message(form.subject.data, sender='PHIS_TRAP@example.com', recipients=['your_email@example.com'])
      msg.body = """
      From: %s &lt;%s&gt;
      %s
      """ % (form.name.data, form.email.data, form.message.data)
      mail.send(msg)
 
      return redirect("/index",)
 
  elif request.method == 'GET':
    return render_template('contact.html', form=form)
        
        
if __name__ == '__main__':
      app.run(host='0.0.0.0',debug=False)