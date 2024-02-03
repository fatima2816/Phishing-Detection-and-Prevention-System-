import re
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import whois
import pickle, joblib
from sklearn.tree import export_text
import pandas
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from flask import Flask, render_template, request
import joblib
import re

app = Flask(__name__)
recently_checked_urls = []

def check_ip(url):
    # Regular expression to match an IP
    ip = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    domain = re.sub(r'^https?://', '', url)
    domain = re.sub(r'/.*$', '', domain)
    if ip.match(domain):
        return 1
    else:
        return 0
    
def check_symbol(url):
    symbol = re.compile(r'@')
    if symbol.search(url):
        return 1
    else:
        return 0
    
def check_Length(url):
  if len(url) < 54:
    leng = 0
  else:
    leng = 1
  return leng

def getDepth(url):
    path = urlparse(url).path
    depth = path.count('/')
    return depth

def redirection(url):
  position = url.rfind('//')
  if position > 6 or position > 7:
      return 1
  else:
      return 0
  
def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1
  else:
    return 0

def check_prefix(url):
    dash = re.compile(r'-')
    # Extract the domain from the URL
    domain = re.sub(r'^https?://', '', url)
    domain = re.sub(r'/.*$', '', domain)
    if dash.search(domain):
        return 1
    else:
        return 0
    
def check_iframe(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if not response.text:
            return 1
        if re.findall(r"[|]", response.text):
            return 0
        else:
            return 1

    except requests.exceptions.RequestException as e:
        # print(f"Error accessing the website: {e}")
        return 1

def StatusBar(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        if not response.text:
            return 1
        if re.findall("", response.text):
            return 0
        else:
            return 1
    except requests.exceptions.RequestException as e:
        # print(f"Error accessing the website: {e}")
        return 1
    
def disablerightClick(url):
  try:
        response = requests.get(url)
        response.raise_for_status()
        if not response.text:
            return 1
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1
  except requests.exceptions.RequestException as e:
        return 1
    
def webforward(url):
  try:
        response = requests.get(url)
        response.raise_for_status()
        if not response.text:
            return 1
        if len(response.history) <= 2:
            return 0
        else:
            return 1
  except requests.exceptions.RequestException as e:
        # print(f"Error accessing the website: {e}")
        return 1
    
def websiteTraffic(url,timeout=10):
    # Check if the website is accessible
    try:
        response = requests.get(url,timeout=timeout)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        # print(f"Error accessing the website: {e}")
        return 1
    except requests.exceptions.Timeout:
        # print(f"Error: Timeout exceeded ({timeout} seconds)")
        return 1

    # Check if the URL is in the Alexa Top Sites is not recognized
    #if the domain has no traffic return 1 for phishing

    try:
        alexa_url = "https://www.alexa.com/topsites"
        alexa_response = requests.get(alexa_url)
        alexa_response.raise_for_status()

        soup = BeautifulSoup(alexa_response.text, 'html.parser')
        if soup.find('a', string=url):
            return 0
        return 1
    except requests.exceptions.RequestException as e:
        # print(f"Error checking Alexa Top Sites: {e}")

        return 0

def calculate_domain_end(domain_info):
    if domain_info is None:
        return 1
    expiration_date = domain_info.expiration_date
    if isinstance(expiration_date, list):
        return 1
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1

    if expiration_date is None:
        return 1

    today = datetime.now()
    remaining_time = abs((expiration_date - today).days) // 30

    return 1 if remaining_time < 6 else 0

def get_domain_info(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        #print(f"Error fetching WHOIS information: {e}")
        return None

def calculate_domain_age(domain_info):
    if domain_info is None:
        return 1
    creation_date = domain_info.creation_date
    expiration_date = domain_info.expiration_date

    # check for lists
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]

   #check for strings
    if isinstance(creation_date, str):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
        except:
            return 1
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
        except:
            return 1

    # Handle cases where expiration_date or creation_date is None
    if expiration_date is None or creation_date is None:
        return 1
    if not (isinstance(expiration_date, datetime) and isinstance(creation_date, datetime)):
        return 1

    # Calculate the age of the domain in months
    age_of_domain = abs((expiration_date - creation_date).days) // 30

    # If age is less than 6 months, consider it suspicious (phishing)
    if age_of_domain < 6:
        return 1
    else:
        return 0

def extract_features_from_link(link):
    
    haveIP = check_ip(link)
    checkSymbol = check_symbol(link)
    lengthURL = check_Length(link)
    depthURL = getDepth(link)
    redirect = redirection(link)
    http_Domain = httpDomain(link)    
    prefix_suffix = check_prefix(link)
    iframe = check_iframe(link)
    status_bar = StatusBar(link)
    disableRightClick = disablerightClick(link)
    webForward = webforward(link)
    website_Traffic = websiteTraffic(link)
    domain_info = get_domain_info (link)
    domain_end = calculate_domain_end(domain_info)
    domain_age = calculate_domain_age(domain_info)
    
    # print(f"Have IP: {haveIP}")
    # print(f"Check Symbol: {checkSymbol}")
    # print(f"Length of URL: {lengthURL}")
    # print(f"Depth of URL: {depthURL}")
    # print(f"Redirect: {redirect}")
    # print(f"HTTP Domain: {http_Domain}")
    # print(f"Prefix or Suffix: {prefix_suffix}")
    # print(f"Check iframe: {iframe}")
    # print(f"Status Bar: {status_bar}")
    # print(f"Disable Right Click: {disableRightClick}")
    # print(f"Web Forward: {webForward}")
    # print(f"Website Traffic: {website_Traffic}")
    # print(f"Domain End: {domain_end}")
    # print(f"Domain Age: {domain_age}")
    
    return [haveIP, checkSymbol, lengthURL, depthURL, redirect, http_Domain, prefix_suffix, domain_age, domain_end, website_Traffic, iframe, status_bar, disableRightClick, webForward]


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        url_input= request.form['urlInput']
        predicted_outcome= DT(url_input)
        print(predicted_outcome)

    # Add the checked URL and its status to the list
    recently_checked_urls.append({"url": url_input, "status": predicted_outcome})


    return render_template('summary.html',url= url_input,result=predicted_outcome, recently_checked_urls=recently_checked_urls)

def DT(new_link):

    file =  "combined_data.csv"
    df = pandas.read_csv(file)

    X = df.drop(['Domain','Label'], axis=1)
    y = df['Label']

    # Extract features from URLs (example: using TF-IDF)
    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(df['Domain'])

    # Split the dataset
    X_train, X_test, y_train, y_test = train_test_split(X,y, test_size=0.2, random_state=42)

    model = joblib.load('decision_tree_model.joblib')
    
    # Make predictions on the test set
    y_pred = model.predict(X_test)

    # new_url = 'http://graphicriver.net/search?date=this-month'
    # new_url = "bafkreiezeywvkuzmgn4iyhms72rfv6gsbcn57wrxuj6btv5ucd3o7stoui.ipfs.cf-ipfs.com"
    # new_url = "https://www.youtube.com/"
    new_url_features = vectorizer.transform([new_link])
    prediction = model.predict(new_url_features)
    
    if prediction[0] == 0:
        print(f"The URL '{new_link}' is predicted to be legitimate.")
        return "legtimate"
    else:
        print(f"The URL '{new_link}' is predicted to be phishing.")
        return "phishing"

  
def RF(new_link):
    new_link = "'http://graphicriver.net/search?date=this-month'"
    features = extract_features_from_link(url_input)
    print("Number of features extracted:", len(features))
    
    loaded_model = joblib.load('random_forest_model.joblib')

    df = pandas.DataFrame([features])
    feature_names = ['Have_IP', 'Have_@', 'URL_Length', 'URL_Depth', 'Redirection', 'https_Domain', 'Prefix/Suffix',
                    'Domain_Age', 'Domain_End', 'Web_Traffic', 'iFrame', 'Status_Bar', 'Right_Click',
                    'Web_Forwards']

    # Set the column names of the DataFrame to the feature names
    df.columns = feature_names
    prediction = loaded_model.predict(df)
    
    # Use the loaded model to make predictions
    predicted_outcome = loaded_model.predict(df)

    # Print the predicted outcome
    print("Predicted Outcome:", predicted_outcome)  

@app.route('/summary')
def summary():
    return render_template('summary.html', url='', result='', recently_checked_urls=recently_checked_urls)

    
if __name__ == '__main__':
    app.run(debug=True)
 