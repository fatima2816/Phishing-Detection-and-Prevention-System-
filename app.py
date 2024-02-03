from flask import Flask, render_template, request
# import joblib
import re

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

# @app.route('/predict', methods=['POST'])
# def predict():
#     if request.method == 'POST':
#         url = request.form['url']

#         # Feature extraction (you may need more sophisticated features)
#         features = [len(url), len(re.findall(r'\d', url)), len(re.findall(r'\W', url))]

#         # Load the trained machine learning model
#         model = joblib.load('phishing_model.pkl')

#         # Make a prediction
#         prediction = model.predict([features])

#         # Display the result
#         return render_template('result.html', url=url, prediction=prediction[0])


if __name__ == '__main__':
    app.run(debug=True)